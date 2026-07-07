package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Release represents the top-level GitHub API release response
type Release struct {
	Assets []Asset `json:"assets"`
}

// Asset represents an individual downloadable binary payload inside a release
type Asset struct {
	Name        string `json:"name"`
	DownloadURL string `json:"browser_download_url"`
}

// AURSearchResponse represents the official Arch RPC search payload format
type AURSearchResponse struct {
	ResultCount int         `json:"resultcount"`
	Results     []AURResult `json:"results"`
}

// AURResult represents an individual package metadata block from the AUR
type AURResult struct {
	Name        string `json:"Name"`
	Version     string `json:"Version"`
	Description string `json:"Description"`
}

// RepoMapping maps a clean app name to its official development repository source
var RepoMapping = map[string]string{
	"fastfetch": "fastfetch-cli/fastfetch",
	"ripgrep":   "BurntSushi/ripgrep",
	"jq":        "jqlang/jq",
}

func printInfoLogo() {
	logo := `
   \x1b[38;5;234m/\x1b[0m\x1b[38;5;234m\\\x1b[0m
  \x1b[38;5;234m/  \x1b[0m\x1b[38;5;234m\\\x1b[0m
 \x1b[38;5;234m/____\x1b[0m\x1b[38;5;234m\\\x1b[0m       \x1b[1;37mSUinstall!\x1b[0m
 \x1b[48;5;108m|  \x1b[32m⟱\x1b[38;5;108m  |\x1b[0m       --------------------------
 \x1b[48;5;108m|_____|\x1b[0m       Arch Linux CLI Package Deployment Subsystem
                       Version: \x1b[1;32m0.8 Beta (Final Preview)\x1b[0m
`
	fmt.Println(strings.ReplaceAll(logo, "\\x1b", "\x1b"))
}

func printUsage() {
	menu := `=========================================================================
  SUPERinstall!  - The AUR HELPER Package Engine
=========================================================================

Core Management Enforcements:
  superinstall -Sy                Synchronize local package databases repositories
  superinstall -Syu               Synchronize databases and execute complete system upgrade
  superinstall -search <query>    Query global and local package availability indexes
  superinstall -S <package>       Validate, sandbox-audit, and install package mapping
  superinstall -info              Display configuration environment layout and logo
  superinstall -git               Scan and pull updates for active VCS development tracks
  superinstall --install-self     Compile and establish tool root entry inside system path`
	fmt.Println(menu)
}

// FEATURE: Security Auditor - Built-in heuristic script scanner
func runSecurityAudit(pkgName, pkgbuildPath string) bool {
	fmt.Printf("\x1b[1;33m:: [Security Auditor]\x1b[0m Scanning build recipes for suspicious sequences...\n")
	file, err := os.Open(pkgbuildPath)
	if err != nil {
		return true 
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	dangerousPatterns := []string{"rm -rf /", "curl ", "wget ", "sudo ", "chmod +x"}
	flagged := false

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		for _, pattern := range dangerousPatterns {
			if strings.Contains(line, pattern) && !strings.HasPrefix(strings.TrimSpace(line), "#") {
				fmt.Printf("  \x1b[1;31m!! WARNING !!\x1b[0m Found '%s' on line %d\n", pattern, lineNum)
				flagged = true
			}
		}
	}

	if flagged {
		fmt.Printf("\x1b[1;31m-> Potential hazard vectors detected.\x1b[0m Do you still wish to execute? [y/N]: ")
		var choice string
		fmt.Scanln(&choice)
		choice = strings.ToLower(strings.TrimSpace(choice))
		return choice == "y" || choice == "yes"
	}

	fmt.Println("  \x1b[1;32m✓\x1b[0m No obvious malicious payload indicators identified.")
	return true
}

// FEATURE: PGP Self-Healing - Automatic developer key import routines
func runPGPHealing(cacheDir string) {
	fmt.Printf("\x1b[1;34m:: [PGP Self-Healing]\x1b[0m Parsing recipe context for identity keys...\n")
	pkgbuildPath := filepath.Join(cacheDir, "PKGBUILD")
	file, err := os.Open(pkgbuildPath)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "validpgpkeys=") {
			cleanLine := strings.NewReplacer("validpgpkeys=", "", "(", "", ")", "", "'", "", "\"", "").Replace(line)
			keys := strings.Fields(cleanLine)
			for _, key := range keys {
				fmt.Printf("  \x1b[1;32m->\x1b[0m Recovering cryptographic developer signature key: %s\n", key)
				_ = exec.Command("gpg", "--recv-keys", key).Run()
			}
		}
	}
}

func searchAUR(query string) {
	fmt.Printf("\x1b[1;32m->\x1b[0m Querying global AUR metadata indexes for '%s'...\n\n", query)
	apiURL := fmt.Sprintf("https://aur.archlinux.org/rpc/?v=5&type=search&arg=%s", query)
	resp, err := http.Get(apiURL)
	if err != nil {
		fmt.Println("Error: Connection failure reaching upstream AUR index streams.")
		return
	}
	defer resp.Body.Close()

	var searchData AURSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchData); err != nil {
		fmt.Println("Error: Metadata response index could not be parsed.")
		return
	}

	if searchData.ResultCount == 0 {
		fmt.Printf("No matching AUR recipe matrix entries found for '%s'.\n", query)
		return
	}

	for _, pkg := range searchData.Results {
		fmt.Printf("\x1b[1;35maur/\x1b[1;37m%s \x1b[1;32m%s\x1b[0m\n", pkg.Name, pkg.Version)
		fmt.Printf("    %s\n", pkg.Description)
	}
}

func reviewPkgbuild(pkgName, pkgbuildPath string) {
	fmt.Printf("\n\x1b[1;33m[Review Prompt]\x1b[0m Would you like to view the PKGBUILD for '%s'? [Y/n]: ", pkgName)
	var response string
	fmt.Scanln(&response)
	response = strings.ToLower(strings.TrimSpace(response))

	if response == "" || response == "y" || response == "yes" {
		cmd := exec.Command("less", pkgbuildPath)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		_ = cmd.Run()
	}
}

func installFromAUR(pkgName string) {
	fmt.Printf("\x1b[1;32m::\x1b[0m Package '%s' not in quick-index. Searching live AUR tracks...\n", pkgName)
	cacheDir := filepath.Join(os.Getenv("HOME"), ".cache/superinstall", pkgName)
	_ = os.MkdirAll(filepath.Join(os.Getenv("HOME"), ".cache/superinstall"), 0755)

	_ = os.RemoveAll(cacheDir)

	fmt.Printf("\x1b[1;34m->\x1b[0m Cloning source tree from: https://aur.archlinux.org/%s.git\n", pkgName)
	cloneCmd := exec.Command("git", "clone", "https://aur.archlinux.org/"+pkgName+".git", cacheDir)
	cloneCmd.Stdout = os.Stdout
	cloneCmd.Stderr = os.Stderr
	if err := cloneCmd.Run(); err != nil {
		fmt.Printf("\x1b[1;31mError:\x1b[0m Package '%s' does not exist in the AUR.\n", pkgName)
		os.Exit(1)
	}

	pkgbuildPath := filepath.Join(cacheDir, "PKGBUILD")
	reviewPkgbuild(pkgName, pkgbuildPath)

	if !runSecurityAudit(pkgName, pkgbuildPath) {
		fmt.Println("Installation aborted due to security flag warnings.")
		os.Exit(1)
	}
	runPGPHealing(cacheDir)

	fmt.Println("\x1b[1;32m::\x1b[0m Starting compilation layout via makepkg...")
	buildCmd := exec.Command("makepkg", "-si", "--noconfirm")
	buildCmd.Dir = cacheDir
	buildCmd.Stdin = os.Stdin
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr

	if err := buildCmd.Run(); err != nil {
		fmt.Printf("\x1b[1;31mError:\x1b[0m Build pipeline processing failed for '%s'.\n", pkgName)
		os.Exit(1)
	}

	fmt.Printf("\n\x1b[1;32m[Success]\x1b[0m Natively deployed '%s' from the AUR!\n", pkgName)
}

func installSelf() {
	fmt.Println("\x1b[1;32m::\x1b[0m Initiating superinstall core self-compilation deployment...")
	homeDir, _ := os.UserHomeDir()
	binDir := filepath.Join(homeDir, ".local/bin")
	_ = os.MkdirAll(binDir, 0755)

	targetBinaryPath := filepath.Join(binDir, "superinstall")
	fmt.Println("\x1b[1;34m->\x1b[0m Compiling production runtime optimized binaries...")
	
	// FIXED: Compiles the directory package context directly. No explicit file tracking constraints needed.
	cmd := exec.Command("go", "build", "-o", targetBinaryPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	
	if err := cmd.Run(); err != nil {
		fmt.Printf("Error: Self-installation build thread failed: %v\n", err)
		os.Exit(1)
	}

	_ = os.Chmod(targetBinaryPath, 0755)
	fmt.Printf("\n\x1b[1;32m[Success]\x1b[0m Linked seamlessly: %s\n", targetBinaryPath)
}

func executePacmanCmd(flags ...string) {
	cmd := exec.Command("sudo", append([]string{"pacman"}, flags...)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf("Pacman Error: Core execution channel closed down with error: %v\n", err)
	}
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	arg := os.Args[1]

	switch arg {
	case "-info":
		printInfoLogo()
		return
	case "--install-self":
		installSelf()
		return
	case "-Sy":
		executePacmanCmd("-Sy")
		return
	case "-Syu":
		executePacmanCmd("-Syu")
		return
	case "-search":
		if len(os.Args) > 2 {
			searchAUR(os.Args[2])
		} else {
			fmt.Println("Error: Missing query string parameters.")
		}
		return
	}

	if arg == "-S" && len(os.Args) > 2 {
		arg = os.Args[2]
	}

	pkg := arg
	_, exists := RepoMapping[pkg]
	if !exists {
		installFromAUR(pkg)
		return
	}

	mprRoot := filepath.Join(os.Getenv("HOME"), ".local/share/superinstall")
	fmt.Printf("[Target Discovery] Host System: %s (%s)\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("Handling index deployment sequence for quick target lookup: %s in %s\n", pkg, mprRoot)
}
// RunSecurityAudit parses a PKGBUILD script line-by-line using contextual heuristic analysis
func RunSecurityAudit(pkgName string, pkgbuildPath string) bool {
	fmt.Printf("\n\x1b[1;33m[Auditor]\x1b[0m Commencing comprehensive heuristic security validation for \x1b[1;37m%s\x1b[0m...\n", pkgName)

	file, err := os.Open(pkgbuildPath)
	if err != nil {
		fmt.Printf("\x1b[1;31m[!] Error:\x1b[0m Unable to open build recipe target for auditing: %v\n", err)
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineCount := 0
	riskScore := 0
	var violations []string

	for scanner.Scan() {
		lineCount++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and direct bash comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 1. Trap Network Pull Vectors (Should be defined globally in source=(), not in scripts)
		if strings.Contains(line, "curl ") || strings.Contains(line, "wget ") || strings.Contains(line, "lynx") {
			violations = append(violations, fmt.Sprintf("Line %d: Hidden remote network download vector detected", lineCount))
			riskScore += 4
		}

		// 2. Trap Dangerous Sandbox Escape Violations
		if strings.Contains(line, "rm -rf") {
			// Allow cleanups if strictly bound inside the safe build directory boundaries
			if !strings.Contains(line, "$srcdir") && !strings.Contains(line, "${srcdir}") && 
			   !strings.Contains(line, "$pkgdir") && !strings.Contains(line, "${pkgdir}") {
				violations = append(violations, fmt.Sprintf("Line %d: Unbounded file destruction sequence ('rm -rf')", lineCount))
				riskScore += 5
			}
		}

		// 3. Trap Root Escalation and Identity Modification Markers
		if strings.Contains(line, "sudo ") || strings.Contains(line, "chown ") || strings.Contains(line, "chmod +x") {
			violations = append(violations, fmt.Sprintf("Line %d: Active permissions override or escalation rule", lineCount))
			riskScore += 3
		}

		// 4. Trap Suspicious Direct System Paths Modifications
		if (strings.Contains(line, "/etc/") || strings.Contains(line, "/usr/bin/") || strings.Contains(line, "/boot/")) && 
			!strings.Contains(line, "$pkgdir") && !strings.Contains(line, "${pkgdir}") {
			violations = append(violations, fmt.Sprintf("Line %d: Attempted modification of system root directories outside workspace sandbox", lineCount))
			riskScore += 5
		}
	}

	// Evaluate final audit report findings
	if riskScore > 0 {
		fmt.Printf("\n\x1b[1;31m[!] WARNING: Security Auditor flagged %d potential code vulnerabilities:\x1b[0m\n", len(violations))
		for _, violation := range violations {
			fmt.Printf("  \x1b[1;33m->\x1b[0m %s\n", violation)
		}
		
		fmt.Printf("\n\x1b[1;31m[Risk Evaluation Level: %d/10]\x1b[0m Proceed with native script installation? [y/N]: ", riskScore)
		var response string
		fmt.Scanln(&response)
		response = strings.ToLower(strings.TrimSpace(response))
		
		return response == "y" || response == "yes"
	}

	fmt.Println("\x1b[1;32m[✓] Security Audit Passed:\x1b[0m No suspicious execution paths or sandbox breaking patterns found.")
	return true
}