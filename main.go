// Package main provides a comprehensive subdomain enumeration tool
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"log"
	"sort"
	"strings"
	"sync"

	"github.com/PuerkitoBio/goquery"
	"gopkg.in/yaml.v3"
)

// Config represents the tool configuration
type Config struct {
	AbuseIPDBSession string `yaml:"abuseipdb_session"`
}

// Default configuration
var defaultConfig = Config{
	AbuseIPDBSession: "YOUR-SESSION",
}

// Global variable to control verbose output
var silent bool

// LoadConfig loads configuration from file
func LoadConfig() Config {
	config := defaultConfig

	// Try to load from user's home directory
	usr, err := user.Current()
	if err == nil {
		configPath := filepath.Join(usr.HomeDir, ".thexrecon.yaml")
		data, err := ioutil.ReadFile(configPath)
		if err == nil {
			if err := yaml.Unmarshal(data, &config); err == nil {
				printLog("Configuration loaded from %s", configPath)
			}
		}
	}

	// Try to load from current directory
	data, err := ioutil.ReadFile(".thexrecon.yaml")
	if err == nil {
		if err := yaml.Unmarshal(data, &config); err == nil {
			printLog("Configuration loaded from .thexrecon.yaml")
		}
	}

	return config
}

// Global configuration
var config Config

// Result represents a collection of subdomains
type Result struct {
	sync.Mutex
	Subdomains map[string]bool
}

// NewResult creates a new Result instance
func NewResult() *Result {
	return &Result{
		Subdomains: make(map[string]bool),
	}
}

// Add adds a subdomain to the result set
func (r *Result) Add(subdomain string) {
	r.Lock()
	defer r.Unlock()
	r.Subdomains[subdomain] = true
}

// AddAll adds multiple subdomains to the result set
func (r *Result) AddAll(subdomains []string) {
	r.Lock()
	defer r.Unlock()
	for _, sub := range subdomains {
		r.Subdomains[sub] = true
	}
}

// GetAll returns all subdomains as a sorted slice
func (r *Result) GetAll() []string {
	r.Lock()
	defer r.Unlock()
	
	var result []string
	for sub := range r.Subdomains {
		result = append(result, sub)
	}
	
	sort.Strings(result)
	return result
}

// Size returns the number of unique subdomains
func (r *Result) Size() int {
	r.Lock()
	defer r.Unlock()
	return len(r.Subdomains)
}

// Helper function for printing logs when not in silent mode
func printLog(format string, args ...interface{}) {
	if !silent {
		fmt.Printf(format+"\n", args...)
	}
}

// AbuseIPDB fetches WHOIS information from AbuseIPDB
func AbuseIPDB(domain string, session string, result *Result) {
	printLog("[+] Running AbuseIPDB for %s", domain)
	
	// Skip if no session is configured
	if session == "" {
		printLog("[!] Skipping AbuseIPDB: No session configured")
		return
	}
	
	url := fmt.Sprintf("https://www.abuseipdb.com/whois/%s", domain)
	client := &http.Client{}
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		printLog("[!] Error creating AbuseIPDB request: %s", err)
		return
	}
	
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36")
	req.AddCookie(&http.Cookie{Name: "abuseipdb_session", Value: session})
	
	resp, err := client.Do(req)
	if err != nil {
		printLog("[!] Error making AbuseIPDB request: %s", err)
		return
	}
	defer resp.Body.Close()
	
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		printLog("[!] Error parsing AbuseIPDB response: %s", err)
		return
	}
	
	var subdomains []string
	doc.Find("li").Each(func(i int, s *goquery.Selection) {
		text := strings.TrimSpace(s.Text())
		if text != "" {
			subdomains = append(subdomains, text+"."+domain)
		}
	})
	
	result.AddAll(subdomains)
}

// SubdomainCenter fetches subdomains from Subdomain Center API
func SubdomainCenter(domain string, result *Result) {
	printLog("[+] Running Subdomain Center for %s", domain)
	
	url := fmt.Sprintf("https://api.subdomain.center/?domain=%s", domain)
	resp, err := http.Get(url)
	if err != nil {
		printLog("[!] Error making Subdomain Center request: %s", err)
		return
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		printLog("[!] Subdomain Center returned non-OK status: %d", resp.StatusCode)
		return
	}
	
	var subdomains []string
	if err := json.NewDecoder(resp.Body).Decode(&subdomains); err != nil {
		printLog("[!] Error decoding Subdomain Center response: %s", err)
		return
	}
	
	result.AddAll(subdomains)
}

// CrtSh fetches subdomains from crt.sh
func CrtSh(domain string, result *Result) {
	printLog("[+] Running crt.sh for %s", domain)
	
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	resp, err := http.Get(url)
	if err != nil {
		printLog("[!] Error making crt.sh request: %s", err)
		return
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		printLog("[!] crt.sh returned non-OK status: %d", resp.StatusCode)
		return
	}
	
	var data []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		printLog("[!] Error decoding crt.sh response: %s", err)
		return
	}
	
	var subdomains []string
	for _, entry := range data {
		if nameValue, ok := entry["name_value"].(string); ok {
			subdomain := strings.Replace(nameValue, "*.", "", -1)
			subdomains = append(subdomains, subdomain)
		}
	}
	
	result.AddAll(subdomains)
}

// RunSubfinder runs subfinder for subdomain enumeration
func RunSubfinder(domain string, result *Result) {
	printLog("[+] Running Subfinder for %s", domain)
	
	cmd := exec.Command("subfinder", "-d", domain, "-all", "-silent")
	output, err := cmd.Output()
	if err != nil {
		printLog("[!] Error running Subfinder: %s", err)
		return
	}
	
	lines := strings.Split(string(output), "\n")
	var subdomains []string
	for _, line := range lines {
		if line != "" && !strings.Contains(line, "*") {
			subdomains = append(subdomains, line)
		}
	}
	
	result.AddAll(subdomains)
}

// RunChaos runs Chaos for subdomain enumeration
func RunChaos(domain string, result *Result) {
	printLog("[+] Running Chaos for %s", domain)
	
	cmd := exec.Command("chaos", "-d", domain, "-silent")
	output, err := cmd.Output()
	if err != nil {
		printLog("[!] Error running Chaos: %s", err)
		return
	}
	
	lines := strings.Split(string(output), "\n")
	var subdomains []string
	for _, line := range lines {
		if line != "" && !strings.Contains(line, "*") {
			subdomains = append(subdomains, line)
		}
	}
	
	result.AddAll(subdomains)
}

// RunGAU runs GAU for subdomain discovery
func RunGAU(domain string, result *Result) {
	printLog("[+] Running GAU for %s", domain)
	
	cmd := exec.Command("gau", domain, "--threads", "10", "--subs")
	output, err := cmd.Output()
	if err != nil {
		printLog("[!] Error running GAU: %s", err)
		return
	}
	
	lines := strings.Split(string(output), "\n")
	var subdomains []string
	for _, line := range lines {
		if line != "" && !strings.Contains(line, "*") {
			subdomains = append(subdomains, line)
		}
	}
	
	result.AddAll(subdomains)
}

// RunWayback fetches subdomains from the Wayback Machine
func RunWayback(domain string, result *Result) {
	printLog("[+] Running Wayback Machine for %s", domain)
	
	cmd := exec.Command("curl", "-s", fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=*%s/*&fl=original&collapse=urlkey", domain))
	output, err := cmd.Output()
	if err != nil {
		printLog("[!] Error running Wayback Machine: %s", err)
		return
	}
	
	lines := strings.Split(string(output), "\n")
	var subdomains []string
	for _, line := range lines {
		if line != "" && !strings.Contains(line, "*") {
			subdomains = append(subdomains, line)
		}
	}
	
	result.AddAll(subdomains)
}

// RunAssetfinder runs assetfinder for subdomain enumeration
func RunAssetfinder(domain string, result *Result) {
	printLog("[+] Running Assetfinder for %s", domain)
	
	cmd := exec.Command("assetfinder", domain)
	output, err := cmd.Output()
	if err != nil {
		printLog("[!] Error running Assetfinder: %s", err)
		return
	}
	
	lines := strings.Split(string(output), "\n")
	var subdomains []string
	for _, line := range lines {
		if line != "" && !strings.Contains(line, "*") {
			subdomains = append(subdomains, line)
		}
	}
	
	result.AddAll(subdomains)
}

// RunAmass runs Amass for subdomain enumeration
func RunAmass(domain string, result *Result) {
	printLog("[+] Running Amass for %s", domain)
	
	cmd := exec.Command("amass", "enum", "-active", "-d", domain)
	output, err := cmd.Output()
	if err != nil {
		printLog("[!] Error running Amass: %s", err)
		return
	}
	
	lines := strings.Split(string(output), "\n")
	var subdomains []string
	for _, line := range lines {
		if line != "" && !strings.Contains(line, "*") {
			subdomains = append(subdomains, line)
		}
	}
	
	result.AddAll(subdomains)
}

// Version represents the current version of the tool
const Version = "1.0.2"

// ProcessDomain runs all subdomain enumeration methods on a domain
func ProcessDomain(domain string) []string {
	printLog("[*] Processing domain: %s", domain)
	
	result := NewResult()
	var wg sync.WaitGroup
	
	wg.Add(9)
	
	go func() {
		defer wg.Done()
		AbuseIPDB(domain, config.AbuseIPDBSession, result)
	}()
	
	go func() {
		defer wg.Done()
		SubdomainCenter(domain, result)
	}()
	
	go func() {
		defer wg.Done()
		RunSubfinder(domain, result)
	}()
	
	go func() {
		defer wg.Done()
		RunChaos(domain, result)
	}()
	
	go func() {
		defer wg.Done()
		CrtSh(domain, result)
	}()
	
	go func() {
		defer wg.Done()
		RunGAU(domain, result)
	}()
	
	go func() {
		defer wg.Done()
		RunWayback(domain, result)
	}()
	
	go func() {
		defer wg.Done()
		RunAssetfinder(domain, result)
	}()
	
	go func() {
		defer wg.Done()
		RunAmass(domain, result)
	}()
	
	wg.Wait()
	
	// Regex for filtering valid subdomains
	subdomainRegex := regexp.MustCompile(`^([a-zA-Z0-9-]+\.){2,}[a-zA-Z]{2,}$`)
	
	cleanResults := NewResult()
	for sub := range result.Subdomains {
		try := func(subdomain string) {
			// Extract domain part only (remove schemes/paths if present)
			parts := strings.Split(subdomain, "//")
			var hostname string
			if len(parts) > 1 {
				hostname = parts[len(parts)-1]
			} else {
				hostname = parts[0]
			}
			
			parts = strings.Split(hostname, "/")
			hostname = parts[0]
			
			if subdomainRegex.MatchString(hostname) {
				cleanResults.Add(hostname)
			}
		}
		
		// Use a function to handle potential panics
		func() {
			defer func() {
				if r := recover(); r != nil {
					printLog("[!] Error processing subdomain '%s': %v", sub, r)
				}
			}()
			try(sub)
		}()
	}
	
	printLog("[+] Found %d clean subdomains for %s", cleanResults.Size(), domain)
	return cleanResults.GetAll()
}

// CheckDependencies checks if all required tools are installed
func CheckDependencies() bool {
	dependencies := []string{
		"subfinder",
		"chaos",
		"gau",
		"curl",
		"assetfinder",
		"amass",
	}
	
	allInstalled := true
	for _, dep := range dependencies {
		cmd := exec.Command("which", dep)
		if err := cmd.Run(); err != nil {
			printLog("[!] Missing dependency: %s", dep)
			allInstalled = false
		} else {
			printLog("[+] Found dependency: %s", dep)
		}
	}
	
	return allInstalled
}

// PrintBanner displays the tool's banner
func PrintBanner() {
	banner := `
████████╗██╗  ██╗███████╗██╗  ██╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
╚══██╔══╝██║  ██║██╔════╝╚██╗██╔╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
   ██║   ███████║█████╗   ╚███╔╝ ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
   ██║   ██╔══██║██╔══╝   ██╔██╗ ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
   ██║   ██║  ██║███████╗██╔╝ ██╗██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
                                                                             
     THEXRECON v%s - Subdomain Enumeration Tool by @thexnumb
     High-Performance Subdomain Discovery using Multiple Sources
     ----------------------------------------------------------
`
	fmt.Printf(banner, Version)
}

func main() {
	// Configure logging
	log.SetOutput(ioutil.Discard) // Disable default logging
	
	// Load configuration
	config = LoadConfig()
	
	// Define command-line flags
	singleDomain := flag.String("u", "", "Single domain to process")
	domainListFile := flag.String("l", "", "Path to a file containing a list of domains")
	outputFile := flag.String("o", "", "Path to the output file (default: stdout)")
	checkDeps := flag.Bool("c", false, "Check dependencies and exit")
	showVersion := flag.Bool("v", false, "Show version information")
	silentMode := flag.Bool("silent", false, "Silent mode - only output subdomains, no banner or logs")
	
	// Parse command-line flags
	flag.Parse()
	
	// Set silent mode global variable
	silent = *silentMode
	
	// Show banner if not in silent mode
	if !silent {
		PrintBanner()
	}
	
	// Show version if requested
	if *showVersion {
		if silent {
			fmt.Printf("%s\n", Version)
		} else {
			fmt.Printf("THEXRECON version %s\n", Version)
		}
		return
	}
	
	// Check dependencies if requested
	if *checkDeps {
		if CheckDependencies() {
			printLog("All dependencies are installed")
		} else {
			printLog("Some dependencies are missing")
		}
		return
	}
	
	// Validate input flags
	if *singleDomain == "" && *domainListFile == "" {
		fmt.Println("Error: Either -u or -l is required")
		flag.Usage()
		os.Exit(1)
	}
	
	if *singleDomain != "" && *domainListFile != "" {
		fmt.Println("Error: Cannot use both -u and -l at the same time")
		flag.Usage()
		os.Exit(1)
	}
	
	var domains []string
	
	// Process single domain
	if *singleDomain != "" {
		domains = append(domains, *singleDomain)
	}
	
	// Process domain list from file
	if *domainListFile != "" {
		file, err := os.Open(*domainListFile)
		if err != nil {
			fmt.Printf("Error opening domain list file: %s\n", err)
			os.Exit(1)
		}
		defer file.Close()
		
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			domain := strings.TrimSpace(scanner.Text())
			if domain != "" && !strings.HasPrefix(domain, "#") {
				domains = append(domains, domain)
			}
		}
		
		if err := scanner.Err(); err != nil {
			fmt.Printf("Error reading domain list file: %s\n", err)
			os.Exit(1)
		}
	}
	
	// Process all domains
	var allResults []string
	for _, domain := range domains {
		results := ProcessDomain(domain)
		allResults = append(allResults, results...)
	}
	
	// Output results
	if *outputFile != "" {
		err := ioutil.WriteFile(*outputFile, []byte(strings.Join(allResults, "\n")), 0644)
		if err != nil {
			fmt.Printf("Error writing to output file: %s\n", err)
			os.Exit(1)
		}
		printLog("[+] Results saved to %s", *outputFile)
	} else {
		// Print to stdout
		for _, result := range allResults {
			fmt.Println(result)
		}
	}
}
