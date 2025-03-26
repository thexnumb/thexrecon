# THEXRECON Subdomain Enumeration Python Tool

A comprehensive python tool for automating subdomain enumeration across multiple bug bounty programs using various techniques and sources.

## Features

- **Multiple Data Sources**: Collects subdomains from various sources including:
  - AbuseIPDB WHOIS information
  - Subdomain.center API
  - Subfinder
  - Chaos
  - Certificate Transparency logs (crt.sh)
  - GetAllUrls (gau)
  - Wayback Machine

- **Organized Structure**: Automatically organizes results by program and domain
- **Deduplication**: Ensures unique subdomains in the output files
- **Filtering**: Removes invalid and wildcard subdomains

## Directory Structure

```
.
├── programs/               # Contains domain lists for each program
│   ├── google.txt          # Example file with domains like google.com, google.nl
│   └── microsoft.txt       # Another example program
├── subdomains/             # Stores discovered subdomains
│   ├── google/             # Subdomains for Google
│   │   ├── google.com.txt
│   │   └── google.nl.txt
│   └── microsoft/
│       └── microsoft.com.txt
│── modules/                # Contains of all modules
│   │── __init__.py
│   │── abuseipdb.py
│   │── subcenter.py
│   │── subfinder.py
│   │── chaos.py
│   │── crtsh.py
│   │── gau.py
│   │── wayback.py
├── requirements.txt
├── thexrecon.py            # Main script that executes all functions
└── README.md               # This documentation
```

## Prerequisites

You need to install the following tools:

```bash
# Install python requirements
pip install -r requirements.txt 

# Install Go-based tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/unfurl@latest
```

Make sure these tools are in your PATH.

## Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/thexnumb/thexrecon.git
   cd thexrecon
   ```

2. Create program files:
   ```bash
   mkdir -p programs
   echo "google.com" > programs/google.txt
   echo "microsoft.com" > programs/microsoft.txt
   ```

3. Make the python script executable:
   ```bash
   chmod +x thexrecon.py
   ```

4. Update the **AbuseIPDB** session cookie:
   - Open `thexrecon.py` and replace `YOUR-SESSION` in the `abuseipdb` function with your actual session cookie

## Usage

### Process all programs

```bash
./thexrecon.py
```

### Check dependencies

```bash
./thexrecon.py -c
```

### Process a specific program

```bash
./thexrecon.py -p google
```

### Process a specific domain in a program

```bash
./thexrecon.py -p google -d google.com
```

### Get help

```bash
./thexrecon.py -h
```

## Adding New Programs

Create a new text file in the `programs/` directory with one domain per line:

```bash
# programs/newprogram.txt
example.com
example.org
other_example.net
```

## Output

The script will create text files containing discovered subdomains in the `subdomains/` directory, organized by program and domain:

```
subdomains/google/google.com.txt
subdomains/microsoft/microsoft.com.txt
```

Each file contains a list of unique subdomains, one per line.

## Customization

You can add or modify functions in the `thexrecon.py` script to include additional data sources or techniques.

## Notes

- Some functions (like `crtsh`) require network access to external services
- The script includes error handling to prevent failures if a particular source is unavailable
- Respect rate limits of the services you're querying to avoid IP blocks

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contact with me 
[![Twitter](https://img.shields.io/badge/X-@thexsecurity-1DA1F2?style=flat&logo=twitter&logoColor=white)](https://x.com/thexsecurity)  
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Profile-blue?style=flat&logo=linkedin)](#)  
[![Medium](https://img.shields.io/badge/Medium-@thexnumb-black?style=flat&logo=medium)](https://medium.com/@thexnumb)  
[![Instagram](https://img.shields.io/badge/Instagram-@thexnumb-E4405F?style=flat&logo=instagram&logoColor=white)](https://instagram.com/thexnumb)  
[![Telegram](https://img.shields.io/badge/Telegram-@thexsecurity-2CA5E0?style=flat&logo=telegram&logoColor=white)](https://t.me/thexsecurity)  
[![YouTube](https://img.shields.io/badge/YouTube-@theXNumb-FF0000?style=flat&logo=youtube&logoColor=white)](https://www.youtube.com/@theXNumb/)  
[![Blogger](https://img.shields.io/badge/Blogger-TheXSecurity-FF5722?style=flat&logo=blogger&logoColor=white)](https://thexsecurity.blogspot.com/)  
[![Infosec.exchange](https://img.shields.io/badge/Infosec.exchange-@thexnumb-E11BE9?style=flat&logo=mastodon&logoColor=white)](https://infosec.exchange/@thexnumb)  

