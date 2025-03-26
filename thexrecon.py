import os
import sys
from modules.abuseipdb import abuseipdb
from modules.subcenter import subcenter
from modules.subfinder import run_subfinder
from modules.chaos import run_chaos
from modules.crtsh import crtsh
from modules.gau import run_gau
from modules.wayback import run_wayback

# Your AbuseIPDB session (replace it)
ABUSEIPDB_SESSION = "YOUR-SESSION"

def process_domain(domain, program):
    """Run all subdomain enumeration methods on a domain."""
    print(f"[*] Processing domain: {domain} for program: {program}")

    os.makedirs(f"subdomains/{program}", exist_ok=True)
    temp_file = f"subdomains/{program}/{domain}.txt"

    results = set()
    
    results.update(abuseipdb(domain, ABUSEIPDB_SESSION))
    results.update(subcenter(domain))
    results.update(run_subfinder(domain))
    results.update(run_chaos(domain))
    results.update(crtsh(domain))
    results.update(run_gau(domain))
    results.update(run_wayback(domain))

    # Save results
    with open(temp_file, "w") as f:
        for sub in sorted(results):
            f.write(f"{sub}\n")

    print(f"[+] Found {len(results)} subdomains for {domain}")

def process_program(program):
    """Process all domains in a program file."""
    program_file = f"programs/{program}.txt"

    if not os.path.exists(program_file):
        print(f"[!] Program file not found: {program_file}")
        sys.exit(1)

    with open(program_file) as f:
        domains = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    for domain in domains:
        process_domain(domain, program)

def main():
    """Main function."""
    if len(sys.argv) > 1:
        if sys.argv[1] == "-p" and len(sys.argv) > 2:
            process_program(sys.argv[2])
        elif sys.argv[1] == "-p" and len(sys.argv) > 3 and sys.argv[3] == "-d" and len(sys.argv) > 4:
            process_domain(sys.argv[4], sys.argv[2])
        else:
            print("Usage: python main.py -p <program> [-d <domain>]")
            sys.exit(1)
    else:
        for program_file in os.listdir("programs"):
            if program_file.endswith(".txt"):
                process_program(program_file.replace(".txt", ""))

if __name__ == "__main__":
    main()
