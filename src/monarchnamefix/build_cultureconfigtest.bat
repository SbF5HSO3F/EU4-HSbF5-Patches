@echo off
rem Build cultureconfigtest.exe (x64 console). ASCII-only.
setlocal
cd /d "%~dp0"
call "%VCVARS64%" >nul 2>&1
if errorlevel 1 ( echo [x] vcvars64 failed & exit /b 1 )
cl /nologo /O2 /MT /W3 /GS- /utf-8 cultureconfigtest.cpp /Fe:cultureconfigtest.exe /Fo:cultureconfigtest.obj /link /MACHINE:X64 /INCREMENTAL:NO
if errorlevel 1 ( echo [x] build failed & exit /b 1 )
del /q cultureconfigtest.obj >nul 2>&1
echo [ok] cultureconfigtest.exe
endlocal
exit /b 0
