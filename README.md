# THEXRECON Subdomain Enumeration Tool

A high-performance Go tool for automating subdomain enumeration across multiple domains using various techniques and sources.

[![Go Report Card](https://goreportcard.com/badge/github.com/thexnumb/thexrecon)](https://goreportcard.com/report/github.com/thexnumb/thexrecon)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **Multiple Data Sources**: Collects subdomains from various sources including:
  - AbuseIPDB WHOIS information
  - Subdomain.center API
  - Subfinder
  - Chaos
  - Certificate Transparency logs (crt.sh)
  - GetAllUrls (gau)
  - Wayback Machine
  - Assetfinder
  - Amass

- **Concurrent Processing**: Uses Go routines for parallel execution of all modules
- **Flexible Input Options**: Process a single domain or a list of domains from a file
- **Flexible Output Options**: Output to stdout or save to a file
- **Deduplication**: Ensures unique subdomains in the output
- **Filtering**: Removes invalid and wildcard subdomains

## Prerequisites

Before installing THEXRECON, make sure you have the following prerequisites:

### 1. Go Installation

You need Go 1.18 or higher installed. If you don't have Go installed:

- **Linux/Mac**: 
  ```bash
  # Download and install Go
  wget https://go.dev/dl/go1.20.4.linux-amd64.tar.gz
  sudo tar -C /usr/local -xzf go1.20.4.linux-amd64.tar.gz
  
  # Add Go to your PATH
  echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.profile
  source ~/.profile
  ```

- **Windows**: Download and install from https://go.dev/dl/

### 2. External Tools

THEXRECON relies on several external tools. Install them with:

```bash
# Install Go-based tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/OWASP/Amass/v3/...@latest
```

Additional requirements:
- `curl` command-line tool (usually pre-installed on most systems)

Make sure these tools are in your PATH.

## Installation

### Option 1: Install directly with Go

```bash
go install github.com/thexnumb/thexrecon@latest
```

This will download, compile, and install the tool to your `$GOPATH/bin` directory, which should be in your PATH.

### Option 2: Clone and build manually

1. Clone the repository:
   ```bash
   git clone https://github.com/thexnumb/thexrecon.git
   cd thexrecon
   ```

2. Build the tool:
   ```bash
   go build -o thexrecon
   ```

3. (Optional) Install to your GOPATH:
   ```bash
   go install
   ```

### Configuration

The tool requires an AbuseIPDB session cookie for one of its modules. You have two ways to configure this:

1. **Config file** (recommended): 
   - Create a file named `.thexrecon.yaml` in your home directory or in the current directory
   - Use the following format:
     ```yaml
     abuseipdb_session: "YOUR-SESSION-COOKIE-HERE"
     ```
   - An example config file is provided as `.thexrecon.yaml.example`

2. **Source code** (for manual installation):
   - Open `main.go` and update the `defaultConfig` variable

To get your AbuseIPDB session cookie:
1. Log in to https://www.abuseipdb.com/
2. Open developer tools (F12)
3. Go to the Application tab
4. Look for the `abuseipdb_session` cookie and copy its value

## Usage

If you installed with `go install`, you can run the tool directly:

```bash
thexrecon -u example.com
```

If you built it manually, run it with:

```bash
./thexrecon -u example.com
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-u domain.com` | Process a single domain |
| `-l domains.txt` | Process multiple domains from a file |
| `-o results.txt` | Save output to a file (otherwise outputs to stdout) |
| `-c` | Check dependencies and exit |
| `-v` | Show version information |
| `-h` | Show help information |

### Examples

Process a single domain:
```bash
thexrecon -u example.com
```

Process multiple domains from a file:
```bash
thexrecon -l domains.txt
```

Save output to a file:
```bash
thexrecon -u example.com -o results.txt
```

Check dependencies:
```bash
thexrecon -c
```

## Input File Format

If using the `-l` option, create a text file with one domain per line:

```
example.com
example.org
other_example.net
```

Comments can be added by prefixing the line with `#`.

## Performance

This tool is optimized for performance by:
- Using Go's concurrency model with goroutines
- Processing multiple sources in parallel
- Efficiently handling and filtering results

## Customization

You can easily extend the tool by adding new modules in the `main.go` file.

## Notes

- Some functions (like `CrtSh`) require network access to external services
- The script includes error handling to prevent failures if a particular source is unavailable
- Respect rate limits of the services you're querying to avoid IP blocks

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🌐 Let's Connect  
[![Discord](https://img.shields.io/badge/Discord-@thexnumb-1DA1F2?style=flat&logo=discord&logoColor=white)](https://discord.gg/evffhtjWR7) [![Twitter](https://img.shields.io/badge/X-@thexsecurity-1DA1F2?style=flat&logo=twitter&logoColor=white)](https://x.com/thexsecurity) [![Telegram](https://img.shields.io/badge/Telegram-@thexsecurity-2CA5E0?style=flat&logo=telegram&logoColor=white)](https://t.me/thexsecurity) [![Instagram](https://img.shields.io/badge/Instagram-@thexnumb-E4405F?style=flat&logo=instagram&logoColor=white)](https://instagram.com/thexnumb) [![Infosec.exchange](https://img.shields.io/badge/Infosec.exchange-@thexnumb-E11BE9?style=flat&logo=mastodon&logoColor=white)](https://infosec.exchange/@thexnumb) [![LinkedIn](https://img.shields.io/badge/LinkedIn-Profile-blue?style=flat&logo=linkedin)](#) [![Medium](https://img.shields.io/badge/Medium-@thexnumb-black?style=flat&logo=medium)](https://medium.com/@thexnumb) [![Blogger](https://img.shields.io/badge/Blogger-TheXSecurity-FF5722?style=flat&logo=blogger&logoColor=white)](https://thexsecurity.blogspot.com/) [![YouTube](https://img.shields.io/badge/YouTube-@theXNumb-FF0000?style=flat&logo=youtube&logoColor=white)](https://www.youtube.com/@theXNumb/) [![Reddit](https://img.shields.io/badge/Reddit-@thexnumb-FF0000?style=flat&logo=reddit&logoColor=white)](https://www.reddit.com/u/thexnumb)
