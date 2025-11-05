# Nuitka Build - Quick Reference

## TL;DR - Quick Fix

**Problem:** Blank webpage and password prompts every time when using compiled exe.

**Solution:** Two fixes applied:

1. **Added missing pdfminer data files** to Nuitka command
2. **Fixed working directory** in main.py so exe finds config/pdfs folders

## Build Command (Windows)

```powershell
# Easy way - use build script
.\build_nuitka.ps1

# Manual way - use updated command with these KEY additions:
#   --include-package=pdfminer
#   --include-package-data=pdfminer
#   (See NUITKA_BUILD_GUIDE.md for full command)
```

## Build Command (Linux)

```bash
# Easy way - use build script
./build_nuitka.sh

# Manual way - see NUITKA_BUILD_GUIDE.md
```

## What Changed

### 1. Code Changes (main.py:107-132)

Added `fix_working_directory()` function that:
- Detects if running as compiled exe
- Changes working directory to exe location (not temp dir)
- Ensures config/pdfs folders are found

### 2. Build Script Changes

Created three build scripts:
- `build_nuitka.bat` (Windows CMD)
- `build_nuitka.ps1` (Windows PowerShell - **recommended**)
- `build_nuitka.sh` (Linux/macOS)

Key additions to Nuitka command:
```bash
--include-package=pdfminer          # Include pdfminer package
--include-package-data=pdfminer     # Include pdfminer data files
--nofollow-import-to=pytest         # Exclude test packages
--nofollow-import-to=test
--nofollow-import-to=tests
```

## Testing the Fix

### Step 1: Build

```powershell
.\build_nuitka.ps1
```

Wait 10-20 minutes for first build.

### Step 2: Deploy

```bash
mkdir TestApp
cd TestApp
copy ..\AjeerAutomation.exe .
```

### Step 3: Run

```bash
.\AjeerAutomation.exe
```

Should:
- ✓ Create pdfs/, config/, etc. folders
- ✓ Prompt for initial setup (if first time)
- ✓ Remember password after first time
- ✓ Extract PDF data correctly (no blank fields)

### Step 4: Verify

Place a test PDF in `pdfs/` folder and run again:

```bash
.\AjeerAutomation.exe
```

Should:
- ✓ Not ask for password (config found)
- ✓ Process PDF successfully (data extracted)
- ✓ Move PDF to processed/ folder
- ✓ No errors about missing modules

## Common Issues & Quick Fixes

### Issue: "Playwright browsers not found"

```bash
python -m playwright install chromium
```

### Issue: Still asks for password every time

**Cause:** Old exe without working directory fix

**Fix:**
1. Verify main.py has `fix_working_directory()` at line 107-132
2. Rebuild exe
3. Delete old exe and use new one

### Issue: Still getting blank form

**Cause:** Old build without pdfminer data

**Fix:**
1. Verify build command has `--include-package-data=pdfminer`
2. Rebuild exe
3. Test with known-good PDF

### Issue: "Another instance running"

```bash
# Windows
taskkill /F /IM AjeerAutomation.exe

# Linux
killall AjeerAutomation
```

## Debug Mode

To see detailed output:

```bash
# Windows CMD
set AJEER_DEBUG=true
.\AjeerAutomation.exe

# Windows PowerShell
$env:AJEER_DEBUG="true"
.\AjeerAutomation.exe

# Linux
export AJEER_DEBUG=true
./AjeerAutomation
```

Look for these in output:
- `Working directory set to: [path]` - Working dir fix is working
- `PDFProcessor created` - PDF processor initialized
- `Extracting PDF data...` - PDF extraction started
- `✓ PDF uploaded` - Data extracted successfully

## File Checklist

After building, you should have:

```
✓ AjeerAutomation.exe (or AjeerAutomation on Linux)
✓ build_nuitka.bat
✓ build_nuitka.ps1
✓ build_nuitka.sh
✓ NUITKA_BUILD_GUIDE.md (full documentation)
✓ NUITKA_QUICK_REFERENCE.md (this file)
```

## Before/After Comparison

### Before (Original Command)

❌ Missing `--include-package=pdfminer`
❌ Missing `--include-package-data=pdfminer`
❌ No working directory fix in code
❌ Result: Blank form, password every time

### After (Fixed Command + Code)

✅ Added `--include-package=pdfminer`
✅ Added `--include-package-data=pdfminer`
✅ Added `fix_working_directory()` in main.py
✅ Result: Working correctly

## One-Liner Test

```bash
# Build
.\build_nuitka.ps1

# Test (after build completes)
mkdir test && cd test && copy ..\AjeerAutomation.exe . && .\AjeerAutomation.exe

# Should work without errors
```

## Need More Help?

See `NUITKA_BUILD_GUIDE.md` for:
- Detailed explanation of root causes
- Complete troubleshooting guide
- Advanced configuration options
- Security considerations
- Performance optimization tips

## Quick Links

- **Full Guide:** NUITKA_BUILD_GUIDE.md
- **Main Code:** main.py (see line 107-132 for fix)
- **Build Scripts:** build_nuitka.ps1 (Windows) / build_nuitka.sh (Linux)
- **Nuitka Docs:** https://nuitka.net/doc/

---

**Version:** 1.0.8
**Last Updated:** 2025-11-05
**Status:** ✓ Fixed and tested
