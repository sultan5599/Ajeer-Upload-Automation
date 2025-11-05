#!/usr/bin/env python3
"""
Ajeer Automation System - Setup Script
Generates encrypted configuration file
"""

import os
import sys
import json
import base64
import hmac
import hashlib
import getpass
from pathlib import Path

# Import crypto dependencies
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

VERSION = "1.0.8"

def generate_key_from_password(password: str, salt: bytes) -> bytes:
    """Generate encryption key from password"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )
    return kdf.derive(password.encode())

def save_config(config_data: dict, password: str, config_path: Path):
    """Save encrypted configuration"""
    # Generate random salt
    salt = os.urandom(32)
    
    # Derive master key from password
    master_key = generate_key_from_password(password, salt)
    
    # Derive separate keys via HKDF
    enc_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ajeer-config-enc',
    ).derive(master_key)
    
    mac_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ajeer-config-mac',
    ).derive(master_key)
    
    # Encrypt configuration
    fernet_key = base64.urlsafe_b64encode(enc_key)
    fernet = Fernet(fernet_key)
    config_json = json.dumps(config_data).encode()
    encrypted_config = fernet.encrypt(config_json)
    
    # Calculate HMAC
    config_hmac = hmac.new(mac_key, encrypted_config, hashlib.sha256).digest()
    
    # Combine: salt + hmac + encrypted_data
    final_data = salt + config_hmac + encrypted_config
    
    # Save to file
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with open(config_path, 'wb') as f:
        f.write(final_data)
    
    # Set restrictive permissions
    try:
        config_path.chmod(0o600)
    except Exception:
        pass

def install_playwright_browsers():
    """Install Playwright Chromium browser"""
    print("\n--- Installing Playwright Browser ---")
    print("This may take a few minutes (downloading ~150MB)...")
    
    try:
        import subprocess
        
        # Install chromium browser
        result = subprocess.run(
            [sys.executable, '-m', 'playwright', 'install', 'chromium'],
            capture_output=True,
            text=True,
            timeout=600  # 10 minutes timeout
        )
        
        if result.returncode == 0:
            print("✓ Chromium browser installed successfully")
            return True
        else:
            print(f"✗ Browser installation failed: {result.stderr}")
            print("\nYou can install it manually later with:")
            print("  python -m playwright install chromium")
            return False
            
    except subprocess.TimeoutExpired:
        print("✗ Installation timed out")
        print("\nPlease run manually:")
        print("  python -m playwright install chromium")
        return False
    except Exception as e:
        print(f"✗ Installation error: {e}")
        print("\nPlease run manually:")
        print("  python -m playwright install chromium")
        return False

def get_default_config():
    """Get default configuration template"""
    return {
        # Target website
        "target_url": "",
        "expected_domain": "",
        
        # SSO domains (optional)
        "allowed_sso_domains": [
            "login.microsoftonline.com",
            "auth.okta.com"
        ],
        
        # Browser settings
        "headless": False,  # Set to True for background operation
        
        # Safety settings
        "force_actions": False,  # Requires AJEER_FORCE_MODE env var too
        "auto_confirm_dialogs": True,
        
        # Rate limiting
        "max_daily_submissions": 100,
        "delay_between_submissions": 5,
        
        # Validation patterns
        "employee_id_pattern": r"^[A-Z0-9]{4,20}$",
        "ajeer_id_pattern": r"^TQ\d{5,}$",
        
        # Optional features
        "av_scan_cli": "",  # Path to antivirus CLI scanner
        "encrypt_before_purge": False
    }

def interactive_setup():
    """Interactive configuration setup"""
    print(f"✓ Created required directories")
    
    # Install Playwright browsers
    install_success = install_playwright_browsers()
    
    print("\n" + "="*60)
    print("Setup Complete!".center(60))
    
    config = get_default_config()
    
    print("This wizard will help you create the encrypted configuration.")
    print("Press Enter to accept default values shown in [brackets]\n")
    
    # Basic settings
    print("--- Basic Settings ---")
    target = input(f"Target URL [{config['target_url']}]: ").strip()
    if target:
        config['target_url'] = target
        # Extract domain from URL
        from urllib.parse import urlparse
        parsed = urlparse(target)
        if parsed.hostname:
            config['expected_domain'] = parsed.hostname
    
    domain = input(f"Expected domain [{config['expected_domain']}]: ").strip()
    if domain:
        config['expected_domain'] = domain
    
    # Browser settings
    print("\n--- Browser Settings ---")
    headless = input(f"Run in headless mode? (yes/no) [no]: ").strip().lower()
    config['headless'] = headless in ['yes', 'y']
    
    auto_confirm = input(f"Auto-confirm submissions? (yes/no) [yes]: ").strip().lower()
    if auto_confirm in ['no', 'n']:
        config['auto_confirm_dialogs'] = False
    
    # Rate limiting
    print("\n--- Rate Limiting ---")
    max_daily = input(f"Max daily submissions [{config['max_daily_submissions']}]: ").strip()
    if max_daily.isdigit():
        config['max_daily_submissions'] = int(max_daily)
    
    delay = input(f"Delay between submissions (seconds) [{config['delay_between_submissions']}]: ").strip()
    if delay.isdigit():
        config['delay_between_submissions'] = int(delay)
    
    # SSO domains
    print("\n--- SSO Configuration (Optional) ---")
    print("Current SSO domains:")
    for domain in config['allowed_sso_domains']:
        print(f"  - {domain}")
    
    add_sso = input("Add/modify SSO domains? (yes/no) [no]: ").strip().lower()
    if add_sso in ['yes', 'y']:
        config['allowed_sso_domains'] = []
        while True:
            sso_domain = input("Enter SSO domain (or press Enter to finish): ").strip()
            if not sso_domain:
                break
            config['allowed_sso_domains'].append(sso_domain)
    
    # Validation patterns
    print("\n--- Validation Patterns ---")
    print(f"Current employee ID pattern: {config['employee_id_pattern']}")
    emp_pattern = input("New employee ID pattern (or Enter to keep): ").strip()
    if emp_pattern:
        config['employee_id_pattern'] = emp_pattern
    
    print(f"Current Ajeer ID pattern: {config['ajeer_id_pattern']}")
    ajeer_pattern = input("New Ajeer ID pattern (or Enter to keep): ").strip()
    if ajeer_pattern:
        config['ajeer_id_pattern'] = ajeer_pattern
    
    # Master password
    print("\n--- Security ---")
    print("Choose a strong master password to encrypt the configuration.")
    print("You will need this password every time you run the automation.\n")
    
    while True:
        password1 = getpass.getpass("Master password: ")
        if len(password1) < 8:
            print("✗ Password must be at least 8 characters")
            continue
        
        password2 = getpass.getpass("Confirm password: ")
        if password1 != password2:
            print("✗ Passwords don't match")
            continue
        
        break
    
    # Save configuration
    print("\n--- Saving Configuration ---")
    config_path = Path('config/settings.encrypted')
    
    try:
        save_config(config, password1, config_path)
        print(f"✓ Configuration saved to: {config_path}")
        print(f"✓ File permissions set to owner-only")
        
        # Create required directories
        for dir_name in ['pdfs', 'processed', 'failed', 'state', 'logs']:
            dir_path = Path(dir_name)
            dir_path.mkdir(exist_ok=True)
            try:
                dir_path.chmod(0o700)
            except Exception:
                pass
        
        print(f"✓ Created required directories")
        
        print("\n" + "="*60)
        print("Setup Complete!".center(60))
        print("="*60)
        print("\nNext steps:")
        print("1. Place PDF files in the 'pdfs/' directory")
        print("2. Run: python main.py")
        print("3. Enter your master password when prompted")
        print("\nFor debug output: export AJEER_DEBUG=true")
        print("For quiet mode: export AJEER_QUIET=true")
        
    except Exception as e:
        print(f"✗ Failed to save configuration: {e}")
        return False
    
    return True

def quick_setup():
    """Quick setup with minimal prompts"""
    print("\n" + "="*60)
    print(f"Ajeer Automation Quick Setup v{VERSION}".center(60))
    print("="*60 + "\n")
    
    config = get_default_config()
    
    # Just get essential info
    target = input("Target URL: ").strip()
    if not target:
        print("✗ Target URL is required")
        return False
    
    config['target_url'] = target
    from urllib.parse import urlparse
    parsed = urlparse(target)
    if parsed.hostname:
        config['expected_domain'] = parsed.hostname
    
    print("\nChoose a master password (min 8 characters):")
    while True:
        password1 = getpass.getpass("Password: ")
        if len(password1) < 8:
            print("✗ Too short")
            continue
        password2 = getpass.getpass("Confirm: ")
        if password1 != password2:
            print("✗ Don't match")
            continue
        break
    
    # Save with defaults
    config_path = Path('config/settings.encrypted')
    try:
        save_config(config, password1, config_path)
        
        # Create directories
        for dir_name in ['pdfs', 'processed', 'failed', 'state', 'logs']:
            Path(dir_name).mkdir(exist_ok=True)
        
        # Install Playwright browsers
        install_playwright_browsers()
        
        print(f"\n✓ Setup complete!")
        print(f"✓ Configuration: {config_path}")
        print(f"✓ Place PDFs in: pdfs/")
        print(f"✓ Run with: python main.py")
        
        return True
    except Exception as e:
        print(f"✗ Setup failed: {e}")
        return False

def main():
    """Main entry point"""
    if len(sys.argv) > 1 and sys.argv[1] == '--quick':
        success = quick_setup()
    else:
        success = interactive_setup()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()