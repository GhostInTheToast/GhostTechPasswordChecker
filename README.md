# GhostTech Password Strength & Breach Checker
**Author:** GhostTech Enterprise LLC

A lightweight CLI tool for assessing password strength and checking whether a password has appeared in known data breaches. Uses secure practices including k-anonymity for breach checking and no plain-text password storage.

## Features

- **Password Strength Assessment**: Comprehensive analysis including:
  - Length scoring (minimum 8 characters recommended)
  - Character diversity (uppercase, lowercase, digits, symbols)
  - Shannon entropy calculation
  - Common password and pattern detection
  - Estimated crack time calculation

- **Breach Checking**: Secure integration with Have I Been Pwned API
  - Uses k-anonymity model (only first 5 chars of SHA-1 hash sent)
  - No plain-text passwords transmitted
  - Reports breach count if found

- **Security Features**:
  - Secure password input (no terminal echo)
  - No password storage or logging
  - Optional breach checking
  - Color-coded output for easy interpretation

## Installation

### Requirements
- Python 3.6+

### Dependencies
```bash
# Required for breach checking (optional)
pip install requests

# Required for colored output (optional)
pip install colorama
```

The tool works without these dependencies but with reduced functionality.

## Usage

### Interactive Mode (Recommended)
```bash
python3 pw_check_gh.py
```
Prompts for password securely (no echo).

### Command Line Mode
```bash
# Check specific password (less secure - visible in command history)
python3 pw_check_gh.py -p "your_password_here"

# Skip breach checking
python3 pw_check_gh.py --no-breach

# Verbose output
python3 pw_check_gh.py -v
```

### Options
- `-p, --password`: Specify password directly (not recommended for security)
- `--no-breach`: Skip Have I Been Pwned breach checking
- `-v, --verbose`: Enable verbose output
- `-h, --help`: Show help message

## Example Output

```
🔒 GhostTech Password Checker
   Secure password strength assessment

==================================================
🔒 GHOSTTECH PASSWORD ANALYSIS REPORT
==================================================

🎯 Overall Strength: STRONG (75/100)

📊 Technical Analysis:
   • Length: 12 characters
   • Character Types: 4/4
   • Entropy: 3.58 bits
   • Estimated Crack Time: 2.3 years

💡 Suggestions:
   • Consider using 16+ characters for maximum security

✅ Good news: Password not found in known breaches
==================================================
```

## Security Notes

- **K-Anonymity**: Breach checking uses only the first 5 characters of your password's SHA-1 hash
- **No Storage**: Passwords are never stored, logged, or transmitted in plain text
- **Secure Input**: Interactive mode uses `getpass` to hide password input
- **Local Processing**: All strength analysis is performed locally

## Exit Codes

- `0`: Password is acceptable (FAIR/STRONG/VERY_STRONG and not breached)
- `1`: Password is weak (VERY_WEAK/WEAK)
- `2`: Password found in breaches

## About

This tool demonstrates cybersecurity best practices including:
- Secure API integration using k-anonymity
- Password entropy and complexity analysis
- Common attack vector awareness
- Defensive security principles

Created by GhostTech Enterprise LLC as a practical security utility.
