from fastapi import APIRouter
from app.api.endpoints import auth, targets, scans

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(targets.router)
api_router.include_router(scans.router)
