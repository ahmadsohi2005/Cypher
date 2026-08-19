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


app = FastAPI(title="Cybersecurity Toolkit API")

origins = [ 
    "http://localhost:5173", 
    "https://cypher-1d7g-gamma.vercel.app"
]

# Enable CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
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
