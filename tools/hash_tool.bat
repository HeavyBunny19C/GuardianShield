@echo off
python "%~dp0hash_tool.py" %*
if %errorlevel% neq 0 pause
