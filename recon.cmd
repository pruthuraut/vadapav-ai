@echo off
setlocal
if "%~1"=="" (
  echo Usage: recon.cmd ^<domain^>
  exit /b 2
)
where py >nul 2>nul
if %ERRORLEVEL%==0 (
  py -3 -m bb_harness --target "%~1" --mode host --run all --export json
) else (
  python -m bb_harness --target "%~1" --mode host --run all --export json
)
