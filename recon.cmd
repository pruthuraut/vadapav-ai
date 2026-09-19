@echo off
setlocal
if "%~1"=="" (
  echo Usage: recon.cmd ^<domain^> [host^|container]
  exit /b 2
)
set MODE=%~2
if "%MODE%"=="" set MODE=container
python -m bb_harness --target "%~1" --mode "%MODE%" --run all --export json
