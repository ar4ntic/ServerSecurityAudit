# Server Security Audit Tool

A comprehensive security audit tool that runs various security checks on target servers, including port scanning, DNS enumeration, certificate analysis, and more.

## Features

- Easy installation with a simple command
- Various security checks including port scanning, DNS enumeration, and certificate analysis
- Supports both graphical interface and command-line usage
- Comprehensive security checks to identify common vulnerabilities

## Installation

The tool automatically installs all required components to your home directory:

```bash
python Install.py
```

### Installation Options

- `--no-venv`: Skip virtual environment creation
- `--skip-wordlists`: Skip downloading wordlists (minimal wordlist will be created instead)
- `--interactive`: Run installer in interactive mode with configuration prompts

### Required External Tools

The following tools must be installed on your system:

- nmap
- nikto
- sslscan
- gobuster
- dig (dnsutils)
- openssl
- curl
- git (for downloading wordlists)

The installer will check for these tools and warn if any are missing.

## Usage

### Using the Graphical Interface

Simply run:

```bash
python StartAudit.py
```

The graphical interface will guide you through configuring and running security checks.

### Command Line Usage

Run security checks on a target:

```bash
python StartAudit.py --target example.com
```

#### Additional Options

- `--checks ping port_scan bruteforce dns cert headers`: Run specific checks only
- `--gui`: Run with GUI progress interface
- `--headless`: Force headless mode (command-line only)
- `--install`: Run the installer before starting the audit
- `--version`: Show version information

## What Gets Installed

The tool creates a `.ServerSecurityAudit` directory in your home folder containing:

- Virtual environment with all required Python dependencies
- Wordlists for various security checks
- Log files from your security audits
- Configuration settings

## Available Security Checks

- **Port Scanning**: Identifies open ports and services
- **DNS Enumeration**: Discovers DNS records and potential vulnerabilities
- **Certificate Analysis**: Checks SSL/TLS certificate security
- **HTTP Headers**: Analyzes HTTP security headers
- **Directory Brute Force**: Finds hidden directories and files
- **Ping Check**: Basic connectivity testing

## License

See the [LICENSE](LICENSE) file for details.