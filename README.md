# Firefox_Decrypt_NSS-Delphi

A Delphi-based utility that uses Firefox's native NSS (Network Security Services) library to recover stored passwords. Available in both GUI and console versions.

## ⚠️ Security Notice

This tool is intended for **legitimate password recovery purposes only**, such as:
- Recovering your own forgotten passwords
- Data migration between browsers
- Personal security auditing

Please ensure you have the legal right to access any passwords you attempt to recover.

## 🌟 Features

- **Dual Interface Options**:
  - User-friendly GUI with password list view
  - Command-line interface for automation
  
- **Native Decryption**:
  - Uses Firefox's own NSS library
  - Supports master password protected profiles
  - Handles modern Firefox encryption schemes

- **Profile Management**:
  - Automatic Firefox profile detection
  - Multiple profile support
  - Profile listing and selection

- **Flexible Output**:
  - Human-readable format
  - JSON export
  - CSV export
  - Save to file functionality (GUI version)

## 🏗️ Technical Details

The tool works by:
1. Loading Firefox's NSS library
2. Initializing NSS with the selected profile
3. Accessing the key storage
4. Decrypting stored credentials using native NSS functions

## 🔧 Prerequisites

- Windows operating system
- Mozilla Firefox installed (required for NSS library)
- Delphi development environment (if building from source)
- Required Delphi components:
  - UniDAC (for SQLite database access)
  - VCL (for GUI version)

## 🚀 Usage

### GUI Version
1. Launch the application
2. Select Firefox profile from dropdown
3. Click "Decrypt" button
4. View or export passwords using the menu options

### Console Version
```bash
FirefoxDecrypt.exe [options]

Options:
  -f, --format FORMAT   Output format (human, json, csv)
  -l, --list           List available profiles
  -c, --choice NUMBER  Profile to use (starts with 1)
  -h, --help          Show this help message
```

### Examples

List available profiles:
```bash
FirefoxDecrypt.exe --list
```

Decrypt passwords from specific profile:
```bash
FirefoxDecrypt.exe --choice 1
```

Export as JSON:
```bash
FirefoxDecrypt.exe --format json
```


## 📄 License

This project is intended for educational and recovery purposes only. Please ensure compliance with applicable laws and regulations in your jurisdiction.

## ⚠️ Disclaimer

This tool comes with no warranties or guarantees. Users are responsible for ensuring they have the legal right to access any passwords they attempt to recover. The developers assume no liability for misuse or damage caused by this tool.

<p align="center">Made with ❤️ using Delphi RAD Studio</p>