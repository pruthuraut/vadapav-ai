@echo off
setlocal
if "%~1"=="" (
  echo Usage: recon.cmd ^<domain^>
  exit /b 2
)
python3 -m bb_harness --target "%~1" --mode host --run all --export json
