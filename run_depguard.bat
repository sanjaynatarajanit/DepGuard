@echo off
setlocal enabledelayedexpansion
title DepGuard - Intelligent Dependency Risk Management
color 0B

echo ==============================================================================
echo   _____             _____                     _ 
echo  ^|  __ \           / ____^|                   ^| ^|
echo  ^| ^|  ^| ^| ___ _ __^| ^|  __ _   _  __ _ _ __ __^| ^|
echo  ^| ^|  ^| ^|/ _ \ '_ \ ^| ^|_ ^| ^| ^| ^|/ _` ^| '__/ _` ^|
echo  ^| ^|__^| ^|  __/ ^|_) ^| ^|__^| ^| ^|_^| ^| (_^| ^| ^| ^| (_^| ^|
echo  ^|_____/ \___^| .__/ \_____^|\__,_^|\__,_^|_^|  \__,_^|
echo              ^| ^|                                
echo              ^|_^|  Intelligent Software Dependency Risk Management
echo ==============================================================================
echo [*] Mode: Java Backend + Cyber-Security SOC Frontend (Pure Zero-DB Runtime)
echo [*] Checking Environment & Compiling Backend...

cd /d "%~dp0\backend"
call compile.bat
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Backend compilation failed. Please check Java JDK installation.
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo [+] Backend successfully compiled!
echo [*] Launching DepGuard Engine on http://localhost:8080 ...
echo [*] Opening Web Browser to http://localhost:8080/ ...

start "" http://localhost:8080/

call start_backend.bat
