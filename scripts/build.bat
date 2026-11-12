@echo off
rem Build helper: initializes the MSVC environment, then runs cargo with all arguments.
rem Usage: scripts\build.bat build --release
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (
  echo [avero] Could not initialize the Visual Studio environment.
  exit /b 1
)
cargo %*
exit /b %errorlevel%
