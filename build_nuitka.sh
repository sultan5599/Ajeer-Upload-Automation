#!/bin/bash
# Ajeer Automation - Nuitka Build Script for Linux
# This script compiles the application into a standalone executable

echo "================================================"
echo "Ajeer Automation - Nuitka Compilation Script"
echo "================================================"
echo ""

# Check if main.py exists
if [ ! -f "main.py" ]; then
    echo "ERROR: main.py not found in current directory"
    echo "Please run this script from the project root directory"
    read -p "Press Enter to exit"
    exit 1
fi

echo "[1/4] Checking Nuitka installation..."
if ! python3 -m nuitka --version &> /dev/null; then
    echo "ERROR: Nuitka is not installed"
    echo "Please install with: pip3 install nuitka"
    read -p "Press Enter to exit"
    exit 1
fi
echo "    OK: Nuitka found"

echo ""
echo "[2/4] Checking Playwright browsers..."
PLAYWRIGHT_PATH="$HOME/.cache/ms-playwright"
if [ -d "$PLAYWRIGHT_PATH" ]; then
    echo "    OK: Playwright browsers found at $PLAYWRIGHT_PATH"
else
    echo "    WARNING: Playwright browsers not found"
    echo "    You may need to run: python3 -m playwright install chromium"
fi

echo ""
echo "[3/4] Starting Nuitka compilation..."
echo "    This may take 10-20 minutes depending on your system"
echo "    Please be patient..."
echo ""

python3 -m nuitka main.py \
  --onefile \
  --standalone \
  --enable-plugin=tk-inter \
  --include-package=playwright \
  --include-package=pdfplumber \
  --include-package=pdfminer \
  --include-package-data=pdfminer \
  --include-package=cryptography \
  --include-package=idna \
  --include-package-data=playwright \
  --nofollow-import-to=pytest \
  --nofollow-import-to=test \
  --nofollow-import-to=tests \
  --output-filename=AjeerAutomation

if [ $? -ne 0 ]; then
    echo ""
    echo "================================================"
    echo "ERROR: Compilation failed!"
    echo "================================================"
    echo "Please check the error messages above"
    read -p "Press Enter to exit"
    exit 1
fi

echo ""
echo "================================================"
echo "[4/4] Build Complete!"
echo "================================================"
echo ""
echo "Executable created: AjeerAutomation"
echo ""
echo "IMPORTANT: Before running the executable:"
echo "1. Create a working directory for the application"
echo "2. Copy AjeerAutomation to that directory"
echo "3. Make it executable: chmod +x AjeerAutomation"
echo "4. Run setup first: ./AjeerAutomation (it will prompt for config)"
echo "   OR manually create these folders:"
echo "   - pdfs/          (place PDF files here)"
echo "   - processed/     (successfully processed PDFs)"
echo "   - failed/        (failed PDFs)"
echo "   - config/        (encrypted settings)"
echo "   - state/         (rate limiting and audit logs)"
echo "   - logs/          (debug logs)"
echo ""
echo "5. Ensure Playwright browsers are installed:"
echo "   - Run: python3 -m playwright install chromium"
echo "   - Browsers location: ~/.cache/ms-playwright/"
echo "   - The executable will look for browsers in this location"
echo ""
echo "================================================"
read -p "Press Enter to exit"
