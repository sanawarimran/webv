@echo off
cd /d "%~dp0"
title AegisAI - Detection-Only Vulnerability Scanning Platform (Provilance Technologies)
echo ======================================================================
echo   AegisAI - Enterprise Vulnerability Detection SaaS
echo   Dashboard UI : http://localhost:8000/
echo   Interactive API Docs: http://localhost:8000/docs
echo   Health Check : http://localhost:8000/health
echo ======================================================================

start "" http://localhost:8000/
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
pause
