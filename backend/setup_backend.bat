@echo off
REM Backend Setup Script for SIEM Project

REM Check Python version
python --version

REM Create virtual environment
python -m venv venv

REM Activate virtual environment
call venv\Scripts\activate

REM Upgrade pip
python -m pip install --upgrade pip

REM Install dependencies
pip install -r requirements.txt

REM Run initial tests
pytest tests/

REM Start the backend server
uvicorn src.api.main:app --reload --port 8000
