@echo off
REM Comprehensive SIEM Backend Test Runner

REM Activate virtual environment
call venv\Scripts\activate

REM Set PYTHONPATH
set PYTHONPATH=.

REM Run comprehensive test suite
pytest tests/ ^
    -v ^
    --durations=10 ^
    --cov=src ^
    --cov-report=html ^
    --cov-report=term-missing ^
    -m "not slow" ^
    --maxfail=10

REM Open coverage report
start htmlcov\index.html

REM Deactivate virtual environment
deactivate
