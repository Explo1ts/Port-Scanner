@echo off
cls
echo Installing required Python libraries...
pip install -r requirements.txt

if %ERRORLEVEL% NEQ 0 (
    echo Error occurred during installation. Please check if Python and pip are installed.
    pause
    exit /b
)

echo.
echo Installation complete.
echo.
echo Now running Port Scanner script...
python Portscanner.py

pause
