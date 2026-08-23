import time
from collections import defaultdict
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.requests import Request

class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    In-memory Sliding Window Rate Limiter Middleware for FastAPI.
    Limits the number of requests per IP address within a specific time window.
    Default: 120 requests per minute per IP.
    """
    def __init__(self, app, max_requests: int = 120, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # Mapping: ip_address -> list of timestamps
        self.request_history = defaultdict(list)

    async def dispatch(self, request: Request, call_next):
        # Exempt health check and pre-flight OPTIONS requests from rate limiting
        if request.method == "OPTIONS" or request.url.path in ["/", "/docs", "/openapi.json"]:
            return await call_next(request)

        # Extract client IP (checking X-Forwarded-For if behind reverse proxy like Render)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()
        else:
            client_ip = request.client.host if request.client else "127.0.0.1"

        now = time.time()
        window_start = now - self.window_seconds

        # Clean old timestamps
        timestamps = [t for t in self.request_history[client_ip] if t > window_start]
        
        if len(timestamps) >= self.max_requests:
            retry_after = int(self.window_seconds - (now - timestamps[0])) if timestamps else self.window_seconds
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Rate limit exceeded. Too many requests. Please slow down.",
                    "retry_after_seconds": max(1, retry_after)
                },
                headers={"Retry-After": str(max(1, retry_after))}
            )

        # Record this request
        timestamps.append(now)
        self.request_history[client_ip] = timestamps

        response = await call_next(request)
        return response
