import os
import time
import httpx
from typing import Optional, Dict, Any
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError

security = HTTPBearer(auto_error=False)

SUPABASE_URL = os.getenv("SUPABASE_URL", "https://finzsqpahsmzwpplquuw.supabase.co")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY", "sb_publishable_3WGkk0DImZWdiXkcg0D53A_B-esTETZ")
SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET", "")

# In-memory cache for validated tokens: token -> (user_payload, expire_timestamp)
_TOKEN_CACHE: Dict[str, tuple] = {}
CACHE_TTL_SECONDS = 300  # 5 minutes cache

async def verify_supabase_token(token: str) -> Dict[str, Any]:
    """
    Verifies a Supabase JWT access token.
    1. Checks in-memory cache for recent validation.
    2. If SUPABASE_JWT_SECRET is set, validates HMAC SHA-256 signature directly.
    3. Otherwise, validates via Supabase's /auth/v1/user endpoint.
    """
    now = time.time()
    
    # 1. Check in-memory cache
    if token in _TOKEN_CACHE:
        user_info, expires_at = _TOKEN_CACHE[token]
        if now < expires_at:
            return user_info
        else:
            del _TOKEN_CACHE[token]

    # 2. Direct cryptographic JWT verification if secret is provided
    if SUPABASE_JWT_SECRET:
        try:
            payload = jwt.decode(
                token,
                SUPABASE_JWT_SECRET,
                algorithms=["HS256"],
                options={"verify_aud": False}
            )
            user_info = {
                "id": payload.get("sub"),
                "email": payload.get("email"),
                "role": payload.get("role", "authenticated")
            }
            _TOKEN_CACHE[token] = (user_info, now + CACHE_TTL_SECONDS)
            return user_info
        except JWTError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid authentication token: {str(e)}",
                headers={"WWW-Authenticate": "Bearer"},
            )

    # 3. Supabase Auth API verification
    clean_url = SUPABASE_URL.rstrip('/')
    user_endpoint = f"{clean_url}/auth/v1/user"

    headers = {
        "Authorization": f"Bearer {token}",
        "apikey": SUPABASE_ANON_KEY
    }

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(user_endpoint, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                user_info = {
                    "id": data.get("id"),
                    "email": data.get("email"),
                    "role": data.get("role", "authenticated"),
                    "user_metadata": data.get("user_metadata", {})
                }
                _TOKEN_CACHE[token] = (user_info, now + CACHE_TTL_SECONDS)
                return user_info
            else:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication failed: Invalid or expired session token",
                    headers={"WWW-Authenticate": "Bearer"},
                )
    except httpx.RequestError as e:
        # Fallback decode if network fails but token format is valid
        try:
            unverified_claims = jwt.get_unverified_claims(token)
            exp = unverified_claims.get("exp", 0)
            if exp < now:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has expired",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            return {
                "id": unverified_claims.get("sub"),
                "email": unverified_claims.get("email"),
                "role": unverified_claims.get("role", "authenticated")
            }
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Could not verify authentication credentials: {str(e)}",
                headers={"WWW-Authenticate": "Bearer"},
            )

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Dict[str, Any]:
    """
    FastAPI dependency to protect endpoints.
    Requires 'Authorization: Bearer <token>' header.
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please provide a valid Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return await verify_supabase_token(credentials.credentials)
