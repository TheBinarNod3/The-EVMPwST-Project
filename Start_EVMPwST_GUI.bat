@echo off
setlocal
chcp 65001 > nul
cd /d "%~dp0"
title EVMPwST Secure Messenger v2.0

if not exist "out" mkdir "out"

echo.
echo ====================================================
echo  EVMPwST — Secure Steganographic Messenger v2.0
echo  Building with Gradle...
echo ====================================================
echo.

.\gradlew.bat run --quiet 2>&1
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Build or launch failed. Run: .\gradlew.bat run
    pause
    exit /b %errorlevel%
)
