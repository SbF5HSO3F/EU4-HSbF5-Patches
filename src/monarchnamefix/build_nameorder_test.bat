@echo off
rem Build nameordertest.exe (x64 console). ASCII-only.
setlocal
cd /d "%~dp0"
call "%VCVARS64%" >nul 2>&1
if errorlevel 1 ( echo [x] vcvars64 failed & exit /b 1 )
cl /nologo /O2 /MT /W3 /GS- /utf-8 nameordertest.cpp /Fe:nameordertest.exe /Fo:nameordertest.obj /link /MACHINE:X64 /INCREMENTAL:NO
if errorlevel 1 ( echo [x] build failed & exit /b 1 )
del /q nameordertest.obj >nul 2>&1
echo [ok] nameordertest.exe
endlocal
exit /b 0
