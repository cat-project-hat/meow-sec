@echo off
title MEOW-SEC :: Cat Hacker Toolkit
color 02
cls
echo.
echo  [MEOW-SEC] Booting...
echo.
python "%~dp0meow.py" %*
if errorlevel 1 (
    echo.
    echo  [ERROR] Python not found or error occurred.
    echo  Make sure Python 3.8+ is installed and run:
    echo    pip install -r requirements.txt
    echo.
    pause
)
