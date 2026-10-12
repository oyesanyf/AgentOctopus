@echo off
title HTTP Terminator - Dual Launcher
cd /d "%~dp0"
echo Starting HTTP Terminator (Test Lab Server + ModelFusion Flaw Hunter)...
python start.py %*
pause
