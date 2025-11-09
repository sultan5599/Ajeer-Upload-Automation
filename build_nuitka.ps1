# Ajeer Automation - Nuitka Build Script for Windows (PowerShell)
# This script compiles the application into a standalone executable

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Ajeer Automation - Nuitka Compilation Script" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Check if main.py exists
if (-not (Test-Path "main.py")) {
    Write-Host "ERROR: main.py not found in current directory" -ForegroundColor Red
    Write-Host "Please run this script from the project root directory" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "[1/4] Checking Nuitka installation..." -ForegroundColor Yellow
$nuitkaCheck = python -m nuitka --version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Nuitka is not installed" -ForegroundColor Red
    Write-Host "Please install with: pip install nuitka" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Host "    OK: Nuitka found" -ForegroundColor Green

Write-Host ""
Write-Host "[2/4] Checking Playwright browsers..." -ForegroundColor Yellow
$playwrightPath = Join-Path $env:LOCALAPPDATA "ms-playwright"
if (Test-Path $playwrightPath) {
    Write-Host "    OK: Playwright browsers found at $playwrightPath" -ForegroundColor Green
} else {
    Write-Host "    WARNING: Playwright browsers not found" -ForegroundColor Yellow
    Write-Host "    You may need to run: python -m playwright install chromium" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[3/4] Starting Nuitka compilation..." -ForegroundColor Yellow
Write-Host "    This may take 10-20 minutes depending on your system" -ForegroundColor Yellow
Write-Host "    Please be patient..." -ForegroundColor Yellow
Write-Host ""

# Build the command as an array for better handling
$nuitkaArgs = @(
    "-m", "nuitka", "main.py",
    "--onefile",
    "--standalone",
    "--msvc=latest",
    "--windows-disable-console",
    "--enable-plugin=tk-inter",
    "--include-package=playwright",
    "--include-package=pdfplumber",
    "--include-package=pdfminer",
    "--include-package-data=pdfminer",
    "--include-package=cryptography",
    "--include-package=idna",
    "--include-package-data=playwright",
    "--nofollow-import-to=pytest",
    "--nofollow-import-to=test",
    "--nofollow-import-to=tests",
    "--company-name=Your Company",
    "--product-name=Ajeer Automation",
    "--file-version=1.0.8",
    "--product-version=1.0.8",
    "--file-description=Ajeer Automation System",
    "--output-filename=AjeerAutomation.exe"
)

# Run Nuitka
& python $nuitkaArgs

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "================================================" -ForegroundColor Red
    Write-Host "ERROR: Compilation failed!" -ForegroundColor Red
    Write-Host "================================================" -ForegroundColor Red
    Write-Host "Please check the error messages above" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host ""
Write-Host "================================================" -ForegroundColor Green
Write-Host "[4/4] Build Complete!" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Executable created: AjeerAutomation.exe" -ForegroundColor Cyan
Write-Host ""
Write-Host "IMPORTANT: Before running the executable:" -ForegroundColor Yellow
Write-Host "1. Create a working directory for the application" -ForegroundColor White
Write-Host "2. Copy AjeerAutomation.exe to that directory" -ForegroundColor White
Write-Host "3. Run setup first: AjeerAutomation.exe (it will prompt for config)" -ForegroundColor White
Write-Host "   OR manually create these folders:" -ForegroundColor White
Write-Host "   - pdfs/          (place PDF files here)" -ForegroundColor White
Write-Host "   - processed/     (successfully processed PDFs)" -ForegroundColor White
Write-Host "   - failed/        (failed PDFs)" -ForegroundColor White
Write-Host "   - config/        (encrypted settings)" -ForegroundColor White
Write-Host "   - state/         (rate limiting and audit logs)" -ForegroundColor White
Write-Host "   - logs/          (debug logs)" -ForegroundColor White
Write-Host ""
Write-Host "4. Ensure Playwright browsers are installed:" -ForegroundColor White
Write-Host "   - Run: python -m playwright install chromium" -ForegroundColor White
Write-Host "   - Browsers location: $env:LOCALAPPDATA\ms-playwright\" -ForegroundColor White
Write-Host "   - The exe will look for browsers in this location" -ForegroundColor White
Write-Host ""
Write-Host "================================================" -ForegroundColor Green
Read-Host "Press Enter to exit"
