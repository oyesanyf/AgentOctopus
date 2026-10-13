@echo off
title RFC Hunt Swarm - Multi-Agent Protocol Research Factory
cd /d "%~dp0"
echo Starting RFC Hunt Swarm Agent (All Modes, Timeout 900s)...
python -u rfc_hunt_swarm.py --mode all --timeout 900 %*
pause
