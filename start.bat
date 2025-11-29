@echo off
REM Quick start script - checks if setup is needed

if not exist "sessions.db" (
    echo ========================================
    echo   Database not found!
    echo ========================================
    echo.
    echo It looks like you haven't run setup yet.
    echo.
    choice /C YN /M "Would you like to run setup now"
    if errorlevel 2 goto :nossetup
    if errorlevel 1 goto :runsetup
)

:runapp
echo Starting StudySync...
python app.py
goto :end

:runsetup
call setup.bat
goto :runapp

:nosetup
echo.
echo Please run setup.bat first, then try again.
pause
goto :end

:end
