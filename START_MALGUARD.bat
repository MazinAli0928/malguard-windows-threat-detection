@echo off
setlocal
title MALGUARD Launcher
color 0B

cd /d "%~dp0"
set "PROJECT=%CD%"

echo.
echo ============================================================
echo                    MALGUARD LAUNCHER
echo ============================================================
echo.
echo Project: %PROJECT%
echo.

REM ============================================================
REM CHECK REQUIRED FILES
REM ============================================================

if not exist "%PROJECT%\venv\Scripts\python.exe" (
    echo [ERROR] Python virtual environment not found.
    echo Expected:
    echo %PROJECT%\venv\Scripts\python.exe
    pause
    exit /b 1
)

if not exist "%PROJECT%\frontend\package.json" (
    echo [ERROR] Frontend package.json not found.
    echo Expected:
    echo %PROJECT%\frontend\package.json
    pause
    exit /b 1
)

REM ============================================================
REM START BACKEND
REM ============================================================

echo [1/3] Starting FastAPI backend...

start "MALGUARD BACKEND" cmd /k ^
cd /d "%PROJECT%" ^&^& ^
"%PROJECT%\venv\Scripts\python.exe" -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000

timeout /t 3 /nobreak >nul

REM ============================================================
REM START FRONTEND
REM ============================================================

echo [2/3] Starting React frontend...

start "MALGUARD FRONTEND" cmd /k ^
cd /d "%PROJECT%\frontend" ^&^& ^
npm run dev

REM ============================================================
REM WAIT FOR VITE
REM ============================================================

echo.
echo Waiting for frontend...
timeout /t 6 /nobreak >nul

REM ============================================================
REM OPEN DASHBOARD
REM ============================================================

echo [3/3] Opening MALGUARD...

start "" "http://localhost:5173"

echo.
echo ============================================================
echo                    MALGUARD STARTED
echo ============================================================
echo.
echo Backend:
echo http://127.0.0.1:8000
echo.
echo Swagger:
echo http://127.0.0.1:8000/docs
echo.
echo Frontend:
echo http://localhost:5173
echo.
echo Keep the BACKEND and FRONTEND windows open.
echo.
pause

endlocal