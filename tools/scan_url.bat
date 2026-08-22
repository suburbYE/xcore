@echo off
cd /d "%~dp0"
echo X-Core Aggregator Sidecar v0.5.3
echo Target: %1
echo.
python aggregator.py url %1 --rules rules/rules.json --visible
echo.
echo Done. Press any key to close...
pause >nul
