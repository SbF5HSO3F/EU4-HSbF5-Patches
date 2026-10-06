@echo off
rem ============================================================
rem  Build MonarchNameFix.dll (x64)
rem  Uses only the local MSVC toolchain (cl.exe + ml64.exe).
rem  No CMake, no ninja, no third-party libraries.
rem  This file is intentionally ASCII-only so cmd.exe never
rem  mis-decodes it.   DO NOT put non-ASCII text in here.
rem
rem  2026-10-05: hook layer rewritten following the approach of the
rem  double-byte patch (EU4dll):
rem    - hook stubs live in stubs.asm and are assembled by ml64
rem    - the install layer is C++ (hookmem.hpp / bytepattern.hpp /
rem      hooks.hpp / install.cpp), mirroring EU4dll's C++ style
rem    - the legacy core stays C (monarchnamefix.c / nameorder.h /
rem      cultureconfig.h) because it is shared with four test
rem      programs that are also C
rem ============================================================
setlocal
cd /d "%~dp0"

set VCVARS="%VCVARS64%"
if not exist %VCVARS% (
  echo [x] vcvars64.bat not found: %VCVARS%
  exit /b 1
)

call %VCVARS% >nul 2>&1
if errorlevel 1 ( echo [x] vcvars64 failed & exit /b 1 )

rem ---- 1) assemble the hook stubs -----------------------------
ml64 /nologo /c /Fo stubs.obj stubs.asm
if errorlevel 1 ( echo [x] ml64 failed on stubs.asm & exit /b 1 )

rem ---- 2) compile + link -------------------------------------
rem /utf-8   : sources are UTF-8
rem /MT      : static CRT
rem /GS-     : no stack cookie for this tiny DLL
rem /std:c++17: install.cpp uses std::string_view / constexpr
rem /EHsc    : standard C++ exception model (only affects .cpp files;
rem             .c files merely emit a D9002 note for the unknown switch)
cl /nologo /LD /O2 /MT /W3 /GS- /utf-8 /DUNICODE /D_UNICODE /std:c++17 /EHsc monarchnamefix.cpp hookvars.cpp install.cpp stubs.obj /Fe:MonarchNameFix.dll /Fo.\ /link /MACHINE:X64 /NOIMPLIB /NOEXP /INCREMENTAL:NO
if errorlevel 1 ( echo [x] build failed & exit /b 1 )

del /q monarchnamefix.obj >nul 2>&1
del /q hookvars.obj >nul 2>&1
del /q install.obj >nul 2>&1
del /q MonarchNameFix.exp >nul 2>&1
del /q MonarchNameFix.lib >nul 2>&1
del /q stubs.obj >nul 2>&1
echo [ok] MonarchNameFix.dll
endlocal
exit /b 0
