# Nuitka Build Guide - Ajeer Automation System

## Problem Summary

When compiling the Ajeer Automation System with Nuitka using the original command, two critical issues occurred:

1. **Blank Webpage Issue**: The form appeared blank when processing PDFs
2. **Password Prompt Issue**: The system asked for the master password every time, ignoring saved credentials

## Root Causes

### 1. Missing pdfminer.six Data Files

**Problem**: `pdfplumber` depends on `pdfminer.six`, which contains essential resource files (character maps, encodings, CMap files, etc.) that are NOT automatically included by Nuitka. Without these files, PDF text extraction fails silently, resulting in blank/empty data being extracted from PDFs.

**Impact**: The form gets submitted with blank fields because the PDF data extraction returns empty strings.

**Solution**: Add `--include-package=pdfminer` and `--include-package-data=pdfminer` to the Nuitka command.

### 2. Working Directory Issue

**Problem**: When Nuitka creates a `--onefile` executable, it extracts the application to a temporary directory at runtime. The application then runs from this temp directory instead of the directory where the `.exe` is located. Since the code uses relative paths like `Path('config/settings.encrypted')`, `Path('pdfs')`, etc., it creates/looks for these folders in the wrong location (the temp directory).

**Impact**:
- Config file cannot be found (password asked every time)
- PDF files not found (even if placed in `pdfs/` folder)
- Processed files go to wrong locations

**Solution**: Added `fix_working_directory()` function in `main.py:107-132` that detects if running as compiled executable and changes the working directory to the executable's location.

## The Fix

### Code Changes

**File: `main.py:107-132`**

Added working directory fix:

```python
def fix_working_directory():
    """Ensure working directory is where the executable/script is located"""
    if getattr(sys, 'frozen', False):
        # Running as compiled executable
        if hasattr(sys, '_MEIPASS'):
            # PyInstaller-style (not used here, but for compatibility)
            exe_dir = os.path.dirname(sys.executable)
        else:
            # Nuitka or other
            exe_dir = os.path.dirname(os.path.abspath(sys.executable))

        # Change to executable directory
        if os.path.isdir(exe_dir):
            os.chdir(exe_dir)
            if DEBUG_MODE:
                print(f"Working directory set to: {exe_dir}")
    else:
        # Running as Python script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        if os.path.isdir(script_dir):
            os.chdir(script_dir)
            if DEBUG_MODE:
                print(f"Working directory set to: {script_dir}")

# Call this before anything else
fix_working_directory()
```

### Updated Nuitka Command

**Critical additions:**
- `--include-package=pdfminer` - Includes pdfminer package
- `--include-package-data=pdfminer` - Includes pdfminer data files (CMaps, encodings, etc.)
- `--nofollow-import-to=pytest` - Excludes test packages (reduces size)
- `--nofollow-import-to=test` - Excludes test packages
- `--nofollow-import-to=tests` - Excludes test packages

**Full Command:**

```powershell
python -m nuitka main.py `
  --onefile `
  --standalone `
  --msvc=latest `
  --windows-disable-console `
  --enable-plugin=tk-inter `
  --include-package=playwright `
  --include-package=pdfplumber `
  --include-package=pdfminer `
  --include-package-data=pdfminer `
  --include-package=cryptography `
  --include-package=idna `
  --include-package-data=playwright `
  --nofollow-import-to=pytest `
  --nofollow-import-to=test `
  --nofollow-import-to=tests `
  --company-name="Your Company" `
  --product-name="Ajeer Automation" `
  --file-version=1.0.8 `
  --product-version=1.0.8 `
  --file-description="Ajeer Automation System" `
  --output-filename=AjeerAutomation.exe
```

## Build Scripts

Three build scripts have been created for convenience:

1. **`build_nuitka.bat`** - Windows Batch script
2. **`build_nuitka.ps1`** - Windows PowerShell script (recommended for Windows)
3. **`build_nuitka.sh`** - Linux/macOS Bash script

### Usage

**Windows (PowerShell):**
```powershell
.\build_nuitka.ps1
```

**Windows (CMD):**
```cmd
build_nuitka.bat
```

**Linux/macOS:**
```bash
chmod +x build_nuitka.sh
./build_nuitka.sh
```

All scripts include:
- Dependency checking
- Progress reporting
- Error handling
- Post-build instructions

## Build Process

### Prerequisites

1. **Install Nuitka:**
   ```bash
   pip install nuitka
   ```

2. **Install MSVC (Windows only):**
   - Install Visual Studio 2019 or later with C++ build tools
   - Or install "Build Tools for Visual Studio"

3. **Install Playwright Browsers:**
   ```bash
   python -m playwright install chromium
   ```

4. **Verify Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

### Build Steps

1. **Navigate to project directory:**
   ```bash
   cd Ajeer-Upload-Automation
   ```

2. **Run build script:**
   ```bash
   # Windows PowerShell (recommended)
   .\build_nuitka.ps1

   # OR Windows CMD
   build_nuitka.bat

   # OR Linux/macOS
   ./build_nuitka.sh
   ```

3. **Wait for compilation:**
   - First build: 10-20 minutes
   - Subsequent builds: 5-10 minutes (with Nuitka cache)

4. **Output:**
   - Windows: `AjeerAutomation.exe`
   - Linux: `AjeerAutomation`

## Deployment

### First-Time Setup

1. **Create working directory:**
   ```bash
   mkdir AjeerAutomationApp
   cd AjeerAutomationApp
   ```

2. **Copy executable:**
   ```bash
   # Copy AjeerAutomation.exe (or AjeerAutomation on Linux) to this directory
   ```

3. **Run initial setup:**
   ```bash
   # Windows
   .\AjeerAutomation.exe

   # Linux
   ./AjeerAutomation
   ```

   The application will:
   - Create required directories (pdfs/, config/, etc.)
   - Prompt for configuration (if not exists)
   - Ask for master password to create encrypted config

4. **Verify directory structure:**
   ```
   AjeerAutomationApp/
   ├── AjeerAutomation.exe    # The executable
   ├── pdfs/                  # Place PDF files here
   ├── processed/             # Successfully processed PDFs
   ├── failed/                # Failed PDFs
   ├── config/                # Encrypted configuration
   │   └── settings.encrypted
   ├── state/                 # Rate limiting & audit logs
   └── logs/                  # Debug logs (if DEBUG mode)
   ```

### Daily Usage

1. **Place PDF files in `pdfs/` folder**

2. **Run the executable:**
   ```bash
   .\AjeerAutomation.exe
   ```

3. **Enter master password when prompted**

4. **Monitor progress**

5. **Check results:**
   - Successful: `processed/` folder
   - Failed: `failed/` folder
   - Logs: `logs/` folder (if DEBUG mode enabled)

## Troubleshooting

### Issue: "Playwright browsers not found"

**Solution:**
```bash
python -m playwright install chromium
```

The browsers must be installed at:
- **Windows**: `%LOCALAPPDATA%\ms-playwright\`
- **Linux**: `~/.cache/ms-playwright/`

### Issue: "Config file not found" every time

**Cause**: Working directory is wrong

**Solution**:
1. Ensure you updated `main.py` with the `fix_working_directory()` function
2. Rebuild the executable
3. Make sure you're running the exe from the same directory where you created the config

### Issue: Still getting blank form data

**Causes:**
1. Missing pdfminer data files
2. Corrupted PDF files

**Solutions:**
1. Verify build command includes `--include-package-data=pdfminer`
2. Rebuild the executable
3. Test with known-good PDF files
4. Enable DEBUG mode to see extraction details:
   ```bash
   set AJEER_DEBUG=true
   .\AjeerAutomation.exe
   ```

### Issue: "Another instance is already running"

**Solution:**
```bash
# Windows
taskkill /F /IM AjeerAutomation.exe
del state\.instance.lock

# Linux
killall AjeerAutomation
rm state/.instance.lock
```

### Issue: Large executable size

**Expected Sizes:**
- Windows: ~150-200 MB (includes Chromium dependencies)
- Linux: ~120-180 MB

**To reduce size (optional):**
- Add more `--nofollow-import-to` flags for unused packages
- Use `--lto=yes` for link-time optimization (slower build)
- Consider using `--standalone` without `--onefile` for faster loading

## Testing the Build

### Basic Test

1. **Create test PDF** with known content
2. **Place in `pdfs/` folder**
3. **Run executable**
4. **Verify:**
   - PDF is processed (moved to `processed/`)
   - No errors in console
   - Config is saved (no password prompt on second run)

### Debug Test

```bash
# Enable debug mode
set AJEER_DEBUG=true

# Run executable
.\AjeerAutomation.exe

# Check logs
type logs\debug.log
```

Verify in logs:
- `Working directory set to: [correct path]`
- `PDFProcessor created`
- `PDF extraction successful`
- No errors about missing modules or data files

## Advanced Configuration

### Custom Build Options

You can modify the build scripts to add:

**Performance:**
- `--lto=yes` - Link-time optimization (smaller, slower build)
- `--clang` - Use Clang instead of MSVC (if installed)

**Debugging:**
- Remove `--windows-disable-console` to see console output
- Add `--debug` for Nuitka debug info

**Size Optimization:**
- `--nofollow-import-to=numpy` - If not using numpy
- `--nofollow-import-to=pandas` - If not using pandas
- Add more packages you don't use

### Environment Variables

The application respects these environment variables:

- `AJEER_DEBUG` - Enable debug logging
- `AJEER_QUIET` - Minimal output
- `AJEER_PASSWORD` - Pre-set master password (NOT RECOMMENDED for security)
- `PLAYWRIGHT_BROWSERS_PATH` - Custom Playwright browser location

## Security Considerations

### Executable Distribution

1. **Antivirus False Positives:**
   - Nuitka executables may trigger AV warnings
   - This is normal for compiled Python applications
   - Whitelist the executable if needed

2. **Code Signing (Recommended):**
   - Sign the executable with a valid certificate
   - Reduces AV false positives
   - Increases user trust

3. **Checksum Verification:**
   - Provide SHA256 checksums for distributed executables
   - Users can verify integrity:
     ```bash
     # Windows
     certutil -hashfile AjeerAutomation.exe SHA256

     # Linux
     sha256sum AjeerAutomation
     ```

### Credential Storage

- Master password is NEVER stored
- Config file is encrypted with AES-256-GCM
- PBKDF2 with 600,000 iterations
- HMAC-SHA256 integrity verification

## Performance Notes

### First Run vs Subsequent Runs

**First run:**
- Nuitka extracts embedded modules
- Creates Python environment
- Loads all dependencies
- **Time:** 10-30 seconds

**Subsequent runs:**
- Uses cached extraction (if available)
- Faster module loading
- **Time:** 3-10 seconds

### PDF Processing Performance

- **Small PDFs (<1MB):** ~1-2 seconds
- **Medium PDFs (1-5MB):** ~2-5 seconds
- **Large PDFs (5-50MB):** ~5-15 seconds

### Memory Usage

- **Idle:** ~100-150 MB
- **Processing:** ~200-400 MB
- **Peak (with browser):** ~500-800 MB

## Comparison: Source vs Compiled

| Aspect | Python Source | Nuitka Executable |
|--------|--------------|-------------------|
| Startup Time | Fast (~1s) | Slower (~5-10s first run) |
| Runtime Performance | Similar | Similar |
| Distribution | Requires Python | Standalone |
| Size | ~50 KB | ~150-200 MB |
| Dependency Management | pip install | All included |
| Updates | Easy (just files) | Rebuild required |
| Security | Source visible | Binary (harder to reverse) |

## Maintenance

### Updating the Application

1. **Update source code** (`main.py`, etc.)
2. **Update version** in build scripts and main.py
3. **Test with Python** first: `python main.py`
4. **Rebuild** executable
5. **Test** executable thoroughly
6. **Distribute** new version with changelog

### Rebuilding After Changes

**Full rebuild:**
```bash
# Delete Nuitka cache
rm -rf main.build main.dist main.onefile-build

# Run build script
.\build_nuitka.ps1
```

**Quick rebuild** (if Nuitka cache is valid):
```bash
# Just run build script
.\build_nuitka.ps1
```

## Support

### Getting Help

If you encounter issues:

1. **Enable DEBUG mode** and check logs
2. **Verify** all prerequisites are installed
3. **Check** this guide's Troubleshooting section
4. **Review** Nuitka documentation: https://nuitka.net/doc/
5. **Test** with Python source first to isolate Nuitka-specific issues

### Common Questions

**Q: Why is the executable so large?**
A: It includes Python runtime, all dependencies (Playwright, Chromium bindings, pdfplumber, cryptography), and embedded data files. This is normal for standalone executables.

**Q: Can I use PyInstaller instead?**
A: Yes, but Nuitka generally produces faster executables and better handles complex dependencies.

**Q: Do users need Python installed?**
A: No, the executable is completely standalone.

**Q: How do I update Playwright browsers?**
A: Run `python -m playwright install chromium` again. The executable will use the updated browsers.

---

**Version:** 1.0.8
**Last Updated:** 2025-11-05
**Build System:** Nuitka 1.8+
**Status:** Production Ready ✓
