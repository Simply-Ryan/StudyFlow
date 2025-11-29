@echo off
REM Quick setup script for Windows users
echo ========================================
echo   StudySync - Windows Setup Script
echo ========================================
echo.

echo [1/3] Installing dependencies...
python -m pip install -r requirements.txt
if errorlevel 1 (
    echo Error: Failed to install dependencies
    pause
    exit /b 1
)

echo.
echo [2/3] Initializing database...
python init_db.py
if errorlevel 1 (
    echo Error: Failed to initialize database
    pause
    exit /b 1
)

echo.
echo [3/3] Setup complete!
echo.
echo ========================================
echo   Ready to run! 
echo ========================================
echo.
echo To start the application:
echo   python app.py
echo.
echo Then open your browser to:
echo   http://127.0.0.1:5000
echo.
pause
