@echo off
setlocal enabledelayedexpansion
echo ==================================================================
echo   DepGuard Security Engine - Compilation Script
echo ==================================================================

cd /d "%~dp0"

set "JAVAC_CMD=C:\Program Files\Java\jdk-27.0.1.0.3\bin\javac.exe"
if not exist "%JAVAC_CMD%" (
    if exist "C:\Program Files\JetBrains\IntelliJ IDEA 2026.2.3\jbr\bin\javac.exe" (
        set "JAVAC_CMD=C:\Program Files\JetBrains\IntelliJ IDEA 2026.2.3\jbr\bin\javac.exe"
    ) else (
        set JAVAC_CMD=javac
    )
)

echo [*] Using Java Compiler: "%JAVAC_CMD%"

if not exist "out" mkdir out

powershell -NoProfile -Command "Get-ChildItem -Path 'src/main/java' -Filter '*.java' -Recurse | ForEach-Object { '\"' + ($_.FullName.Replace('\', '/')) + '\"' } | Out-File -FilePath 'sources.txt' -Encoding ascii"

echo [*] Compiling DepGuard Core Java Sources...
"%JAVAC_CMD%" -encoding UTF-8 -d out @sources.txt

if %ERRORLEVEL% EQU 0 (
    echo [OK] Compilation successful! Class files generated in backend\out\
    if exist sources.txt del sources.txt
) else (
    echo [ERROR] Compilation failed with exit code %ERRORLEVEL%
    exit /b %ERRORLEVEL%
)
