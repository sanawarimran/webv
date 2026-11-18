import os
from fastapi import FastAPI
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.core.database import init_db
from app.api.router import api_router

# Initialize schema
init_db()

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="DETECTION-ONLY vulnerability scanning SaaS by Provilance Technologies",
    version=settings.VERSION,
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix=settings.API_V1_STR)

STATIC_INDEX = os.path.join(os.path.dirname(__file__), "static", "index.html")

@app.get("/", tags=["Dashboard"], response_class=HTMLResponse)
def serve_dashboard():
    if os.path.exists(STATIC_INDEX):
        with open(STATIC_INDEX, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>AegisAI Vulnerability Detection Platform</h1><p>Visit /docs for API.</p>")

@app.get("/dashboard", tags=["Dashboard"], response_class=HTMLResponse)
def serve_dashboard_alias():
    return serve_dashboard()

@app.get("/health", tags=["Health"])
def health():
    return {
        "status": "healthy",
        "organization": settings.ORGANIZATION,
        "version": settings.VERSION
    }
