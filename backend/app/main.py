from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.network_router import router as network_router
from app.api.scanner_router import router as scanner_router
from app.api.osint_router import router as osint_router
from app.api.log_router import router as log_router

import sys
import asyncio

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())


import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="Cybersecurity Toolkit API")

# Configure CORS dynamically from environment or default to local dev ports
env_origins = os.getenv("ALLOWED_ORIGINS")
if env_origins:
    origins = [origin.strip() for origin in env_origins.split(",") if origin.strip()]
else:
    origins = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "https://cypher-lilac.vercel.app"
    ]

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Register routers
app.include_router(network_router)
app.include_router(scanner_router)
app.include_router(osint_router)
app.include_router(log_router)

@app.get("/")
async def health_check():
    return {"status": "Engine is running smoothly"}
