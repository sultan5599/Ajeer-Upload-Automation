@echo off
REM Ajeer Automation - Nuitka Build Script for Windows
REM This script compiles the application into a standalone executable

echo ================================================
echo Ajeer Automation - Nuitka Compilation Script
echo ================================================
echo.

REM Check if main.py exists
if not exist "main.py" (
    echo ERROR: main.py not found in current directory
    echo Please run this script from the project root directory
    pause
    exit /b 1
)

echo [1/4] Checking Nuitka installation...
python -m nuitka --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Nuitka is not installed
    echo Please install with: pip install nuitka
    pause
    exit /b 1
)
echo     OK: Nuitka found

echo.
echo [2/4] Checking Playwright browsers...
python -c "import os; path = os.path.join(os.getenv('LOCALAPPDATA'), 'ms-playwright'); print('Found' if os.path.exists(path) else 'Missing')" 2>nul | findstr "Found" >nul
if errorlevel 1 (
    echo WARNING: Playwright browsers not found
    echo You may need to run: python -m playwright install chromium
    echo.
)

echo.
echo [3/4] Starting Nuitka compilation...
echo     This may take 10-20 minutes depending on your system
echo     Please be patient...
echo.

python -m nuitka main.py ^
  --onefile ^
  --standalone ^
  --msvc=latest ^
  --windows-disable-console ^
  --enable-plugin=tk-inter ^
  --include-package=playwright ^
  --include-package=pdfplumber ^
  --include-package=pdfminer ^
  --include-package-data=pdfminer ^
  --include-package=cryptography ^
  --include-package=idna ^
  --include-package-data=playwright ^
  --nofollow-import-to=pytest ^
  --nofollow-import-to=test ^
  --nofollow-import-to=tests ^
  --company-name="Your Company" ^
  --product-name="Ajeer Automation" ^
  --file-version=1.0.8 ^
  --product-version=1.0.8 ^
  --file-description="Ajeer Automation System" ^
  --output-filename=AjeerAutomation.exe

if errorlevel 1 (
    echo.
    echo ================================================
    echo ERROR: Compilation failed!
    echo ================================================
    echo Please check the error messages above
    pause
    exit /b 1
)

echo.
echo ================================================
echo [4/4] Build Complete!
echo ================================================
echo.
echo Executable created: AjeerAutomation.exe
echo.
echo IMPORTANT: Before running the executable:
echo 1. Create a working directory for the application
echo 2. Copy AjeerAutomation.exe to that directory
echo 3. Run setup first: AjeerAutomation.exe (it will prompt for config)
echo    OR manually create these folders:
echo    - pdfs/          (place PDF files here)
echo    - processed/     (successfully processed PDFs)
echo    - failed/        (failed PDFs)
echo    - config/        (encrypted settings)
echo    - state/         (rate limiting and audit logs)
echo    - logs/          (debug logs)
echo.
echo 4. Ensure Playwright browsers are installed:
echo    - Run: python -m playwright install chromium
echo    - Browsers location: %%LOCALAPPDATA%%\ms-playwright\
echo    - The exe will look for browsers in this location
echo.
echo ================================================
pause
