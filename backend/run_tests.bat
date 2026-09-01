@echo off
REM Activate virtual environment
call venv\Scripts\activate

REM Set PYTHONPATH
set PYTHONPATH=.

REM Run tests with coverage
pytest tests\ --cov=src --cov-report=html

REM Open coverage report
start htmlcov\index.html

REM Deactivate virtual environment
deactivate
