@echo off
echo Installing Python packages...
pip install -r requirements.txt

if %errorlevel% neq 0 (
    echo Error installing Python packages. Please check your internet connection and try again.
    pause
    exit /b %errorlevel%
)

echo Python packages installed successfully.

echo Running bubu-tool.py...
python bubu-tool.py
