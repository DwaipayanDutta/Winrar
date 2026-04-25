# WinRAR Keymaker

A tool to generate WinRAR registration keys using ECDSA SECP256k1 digital signatures.

## Overview

This project generates valid WinRAR .key registration files with ECDSA signatures. It includes:
- `keygen_code.py` - Core Python key generation library using ECDSA
- `RARKeyGenerator.ps1` - PowerShell wrapper script for easy usage

## Requirements

- Python 3.x with `ecdsa` package: `pip install ecdsa`
- PowerShell 5.1+ (Windows)

## Usage

### PowerShell (Recommended)

```powershell
# Default usage - generates key with default username
.\RARKeyGenerator.ps1

# Custom parameters
.\RARKeyGenerator.ps1 -Username "John Doe" -LicenseType "Multi PC license" -OutputDir "C:\Keys"
```

### Python

```python
from keygen_code import RARKeyGenerator

priv_key, pub_key = RARKeyGenerator.generate_keypair()
key_data = RARKeyGenerator.generate_key("Username", "License Type", pub_key)
```

## Installing the Key

Place the generated `.key` file in one of these locations:
- `C:\Program Files\WinRAR` (WinRAR installation directory)
- `%APPDATA%\WinRAR` (User app data folder)

## License Types

Common license types:
- Single PC license
- Multi PC license
- Business license
- Enterprise license