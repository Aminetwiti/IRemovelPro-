@echo off
REM ============================================================================
REM iRemovalClone — Quick start (Windows)
REM ============================================================================

setlocal
set PHP_BIN=php

REM Check PHP availability
where %PHP_BIN% >nul 2>&1
if errorlevel 1 (
    echo [ERROR] PHP not found in PATH
    echo Download from https://windows.php.net/download/
    exit /b 1
)

REM Set up directories
if not exist "var\keys" mkdir "var\keys"
if not exist "var\sessions" mkdir "var\sessions"
if not exist "var\tickets" mkdir "var\tickets"
if not exist "var\logs" mkdir "var\logs"

REM Check for OpenSSL extension
%PHP_BIN% -m | findstr /C:"openssl" >nul
if errorlevel 1 (
    echo [ERROR] OpenSSL extension not enabled in php.ini
    exit /b 1
)

REM Start the server
echo.
echo ======================================================================
echo  iRemovalClone standalone server
echo  Listening on http://127.0.0.1:8080
echo ======================================================================
echo.
echo Endpoints available:
echo   GET  http://127.0.0.1:8080/version33.txt
echo   POST http://127.0.0.1:8080/iremovalActivation/auth3.php
echo   POST http://127.0.0.1:8080/iremovalActivation/checkm8.php
echo   POST http://127.0.0.1:8080/iremovalActivation/iact8.php
echo   POST http://127.0.0.1:8080/iremovalActivation/{ars2,mf5,mf6,mf7}.php
echo   POST http://127.0.0.1:8080/pub.php
echo.
echo Press Ctrl+C to stop
echo.

%PHP_BIN% -S 127.0.0.1:8080 -t . router.php
