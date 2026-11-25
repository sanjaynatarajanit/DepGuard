@echo off
setlocal enabledelayedexpansion
echo ==================================================================
echo   DepGuard Security Engine - Startup Script
echo ==================================================================

cd /d "%~dp0"

set JAVA_CMD=
if exist "C:\Program Files\Java\jdk-27.0.1.0.3\bin\java.exe" (
    set "JAVA_CMD=C:\Program Files\Java\jdk-27.0.1.0.3\bin\java.exe"
) else if exist "C:\Program Files\JetBrains\IntelliJ IDEA 2026.2.3\jbr\bin\java.exe" (
    set "JAVA_CMD=C:\Program Files\JetBrains\IntelliJ IDEA 2026.2.3\jbr\bin\java.exe"
) else (
    set JAVA_CMD=java
)

if not exist "out\com\depguard\DepGuardApplication.class" (
    echo [*] Compiled classes not found. Triggering automated build...
    call compile.bat
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Build failed. Cannot start DepGuard backend.
        pause
        exit /b %ERRORLEVEL%
    )
)

echo [*] Starting DepGuard Risk Management Engine on port 8080...
"%JAVA_CMD%" -cp out com.depguard.DepGuardApplication 8080
