#!/bin/bash

# THEXRECON subdomains enumeration tool created by @thexnumb
# using various tools and techniques.

# Create necessary directories if they don't exist
mkdir -p programs subdomains

# Function to get WHOIS information from AbuseIPDB
abuseipdb() {
    local domain="$1"
    echo "[+] Running AbuseIPDB for $domain" >&2
    curl -s "https://www.abuseipdb.com/whois/$domain" \
        -H "user-agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36" \
        -b "abuseipdb_session=YOUR-SESSION" | \
        grep -E "<li>\w.*</li>" | sed -E "s/<\/?li>//g" | sed "s|$|.$domain|"
}

# Function to query subdomain.center API
subcenter() {
    local domain="$1"
    echo "[+] Running Subdomain Center for $domain" >&2
    curl -s "https://api.subdomain.center/?domain=$domain" | jq -r '.[]'
}

# Function to run subfinder with filtering
nice_subfinder() {
    local domain="$1"
    echo "[+] Running Subfinder for $domain" >&2
    local res
    # Use subfinder directly without zsh (more compatible with GitHub Actions)
    res=$(subfinder -d "$domain" -all -silent)
    echo "$res" | while IFS= read -r sub; do
        if [[ $(echo "$sub" | awk -F'.' '{print NF}') -ne 2 && "$sub" != *"*"* ]]; then
            echo "$sub"
        fi
    done
}

# Function to run chaos with filtering
nice_chaos() {
    local domain="$1"
    echo "[+] Running Chaos for $domain" >&2
    local res
    # Use chaos directly without zsh
    res=$(chaos -d "$domain" -silent)
    echo "$res" | while IFS= read -r sub; do
        if [[ $(echo "$sub" | awk -F'.' '{print NF}') -ne 2 && "$sub" != *"*"* ]]; then
            echo "$sub"
        fi
    done
}

# Function to query crt.sh
crtsh() {
    local domain="$1"
    echo "[+] Running crt.sh for $domain" >&2
    
    # Check if psql is available, otherwise use curl as fallback
    if command -v psql &> /dev/null; then
        query=$(cat <<-END
            SELECT ci.NAME_VALUE FROM certificate_and_identities ci
            WHERE plainto_tsquery('certwatch', '$domain') @@ identities(ci.CERTIFICATE)
END
        )
        echo "$query" | psql -t -h crt.sh -p 5432 -U guest certwatch | sed 's/ //g' | \
        grep -E ".*\.$domain" | sed 's/*\.//g' | tr '[:upper:]' '[:lower:]' | sort -u
    else
        # Fallback to using curl if psql is not available
        echo "[!] psql not available, using curl fallback for crt.sh"
        curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' | \
        sort -u | grep -v "*" | grep -E ".*\.$domain"
    fi
}

# Function to use gau for subdomain discovery
nice_gau() {
    local domain="$1"
    echo "[+] Running GAU for $domain" >&2
    local res
    # Use gau directly without zsh
    res=$(gau "$domain" --threads 10 --subs | unfurl -u domains)
    echo "$res" | while IFS= read -r sub; do
        if [[ $(echo "$sub" | awk -F'.' '{print NF}') -ne 2 && "$sub" != *"*"* ]]; then
            echo "$sub"
        fi
    done
}

# Function to use Wayback Machine for subdomain discovery
nice_wayback() {
    local domain="$1"
    echo "[+] Running Wayback for $domain" >&2
    local res
    res=$(curl -s "https://web.archive.org/cdx/search/cdx?url=*.$domain/*&fl=original&collapse=urlkey" | unfurl -u domains)
    echo "$res" | while IFS= read -r sub; do
        if [[ $(echo "$sub" | awk -F'.' '{print NF}') -ne 2 && "$sub" != *"*"* ]]; then
            echo "$sub"
        fi
    done
}

# Function to process a single domain
process_domain() {
    local domain="$1"
    local program="$2"
    
    echo "[*] Processing domain: $domain for program: $program"
    
    # Create program directory if it doesn't exist
    mkdir -p "subdomains/$program"
    
    # Temporary file for storing results
    temp_file=$(mktemp)
    
    # Run all the enumeration functions and append results to temp file
    # Use || true to continue even if a function fails
    abuseipdb "$domain" 2>/dev/null | tee -a "$temp_file" >/dev/null || true
    subcenter "$domain" 2>/dev/null | tee -a "$temp_file" >/dev/null || true
    nice_subfinder "$domain" 2>/dev/null | tee -a "$temp_file" >/dev/null || true
    nice_chaos "$domain" 2>/dev/null | tee -a "$temp_file" >/dev/null || true
    crtsh "$domain" 2>/dev/null | tee -a "$temp_file" >/dev/null || true
    nice_gau "$domain" 2>/dev/null | tee -a "$temp_file" >/dev/null || true
    nice_wayback "$domain" 2>/dev/null | tee -a "$temp_file" >/dev/null || true
    
    # Remove duplicates and sort
    output_file="subdomains/$program/$domain.txt"
    if [ -f "$output_file" ]; then
        # Merge with existing results
        cat "$temp_file" "$output_file" | grep -v '^$' | sort -u > "$output_file.new"
        mv "$output_file.new" "$output_file"
    else
        # Create new file
        grep -v '^$' "$temp_file" | sort -u > "$output_file"
    fi
    
    # Count the number of subdomains
    subdomain_count=$(wc -l < "$output_file")
    echo "[+] Found $subdomain_count subdomains for $domain"
    
    # Clean up
    rm "$temp_file"
}

# Main function to process all programs
main() {
    # Check if programs directory has files
    if [ -z "$(ls -A programs 2>/dev/null)" ]; then
        echo "[!] No program files found in programs/ directory."
        echo "[!] Please create files in the programs/ directory with domain lists."
        exit 1
    fi
    
    # Loop through all files in programs directory
    for program_file in programs/*.txt; do
        # Extract program name from filename
        program=$(basename "$program_file" .txt)
        echo "[*] Processing program: $program"
        
        # Process each domain in the program file
        while IFS= read -r domain || [ -n "$domain" ]; do
            # Skip empty lines and comments
            if [[ -z "$domain" || "$domain" =~ ^# ]]; then
                continue
            fi
            
            process_domain "$domain" "$program"
        done < "$program_file"
        
        echo "[*] Completed processing program: $program"
    done
    
    echo "[*] All programs processed successfully!"
}

# Check if required tools are installed
check_dependencies() {
    local missing_deps=()
    
    for cmd in curl jq subfinder chaos gau unfurl; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_deps+=("$cmd")
        fi
    done
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        echo "[!] The following dependencies are missing:"
        for dep in "${missing_deps[@]}"; do
            echo "    - $dep"
        done
        echo "[!] Please install them and try again."
        return 1
    fi
    
    return 0
}

# Display usage information
usage() {
    echo "Subdomain Enumeration Automation Script"
    echo "--------------------------------------"
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -h, --help     Display this help message"
    echo "  -c, --check    Check for dependencies"
    echo "  -p, --program  Process a specific program only (e.g., -p google)"
    echo "  -d, --domain   Process a specific domain only (e.g., -d google.com)"
    echo ""
    echo "Examples:"
    echo "  $0                  # Process all programs"
    echo "  $0 -p google        # Process only the google program"
    echo "  $0 -p google -d google.com  # Process only google.com in the google program"
}

# Parse command line arguments
if [ $# -gt 0 ]; then
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        -c|--check)
            check_dependencies
            exit $?
            ;;
        -p|--program)
            if [ -z "$2" ]; then
                echo "[!] Missing program name"
                usage
                exit 1
            fi
            program="$2"
            if [ ! -f "programs/$program.txt" ]; then
                echo "[!] Program file not found: programs/$program.txt"
                exit 1
            fi
            
            # If domain is specified
            if [ "$3" = "-d" ] || [ "$3" = "--domain" ]; then
                if [ -z "$4" ]; then
                    echo "[!] Missing domain name"
                    usage
                    exit 1
                fi
                domain="$4"
                
                # Check if domain exists in program file
                if ! grep -q "^$domain$" "programs/$program.txt"; then
                    echo "[!] Domain $domain not found in program $program"
                    exit 1
                fi
                
                process_domain "$domain" "$program"
                exit 0
            fi
            
            # Process entire program
            echo "[*] Processing program: $program"
            while IFS= read -r domain || [ -n "$domain" ]; do
                # Skip empty lines and comments
                if [[ -z "$domain" || "$domain" =~ ^# ]]; then
                    continue
                fi
                
                process_domain "$domain" "$program"
            done < "programs/$program.txt"
            
            exit 0
            ;;
        -d|--domain)
            echo "[!] Please specify a program with -p before specifying a domain"
            usage
            exit 1
            ;;
        *)
            echo "[!] Unknown option: $1"
            usage
            exit 1
            ;;
    esac
fi

# Run the main function
main
