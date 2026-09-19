@echo off
setlocal
docker compose run --rm --entrypoint python3 bb-harness run_hunt.py %*
endlocal
