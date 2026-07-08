package main

import (
	"bufio"
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// This embeds your source files directly into the final compiled binary
//go:embed main.go go.mod backends/* providers/*
var sourceFiles embed.FS

// Define different risk weights for behaviors
const (
	WeightNetworkDrop   = 40 // Hidden curl/wget download
	WeightObfuscation   = 35 // Base64 decode, eval, hex strings
	WeightSystemWipe    = 50 // Root directory destructions
	WeightPersistence   = 30 // Creating unprompted systemd units
)

// HeuristicRule defines structural checks for malicious intent matching
type HeuristicRule struct {
	Name        string
	Description string
	CheckFn     func(line string) bool
	Weight      int
}

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
	Name        string   `json:"Name"`
	PackageBase string   `json:"PackageBase"`
	Version     string   `json:"Version"`
	Description string   `json:"Description"`
	Depends     []string `json:"Depends"`
	MakeDepends []string `json:"MakeDepends"`
}

// LocalAURPackage internal struct used for system upgrade comparisons
type LocalAURPackage struct {
	Name          string
	LocalVersion  string
	RemoteVersion string
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
                       Version: \x1b[1;32m1.0 Stable Upgrade Track\x1b[0m
`
	fmt.Println(strings.ReplaceAll(logo, "\\x1b", "\x1b"))
}

func printUsage() {
	menu := `=========================================================================
  SUPERinstall!  - The AUR HELPER Package Engine
=========================================================================

Core Management Enforcements:
  superinstall -Sy                 Synchronize local package databases repositories
  superinstall -Syu                Execute Full System Sync and Recursive AUR Upgrade Line
  superinstall -search <query>    Query global and local package availability indexes
  superinstall -S <package>        Validate, sandbox-audit, and install package mapping
  superinstall -info              Display configuration environment layout and logo
  superinstall -git                Scan and pull updates for active VCS development tracks
  superinstall --install-self      Compile and establish tool root entry inside system path`
	fmt.Println(menu)
}

// FEATURE: Advanced Heuristic Security Auditor Engine
func runSecurityAudit(pkgName, pkgbuildPath string) bool {
	fmt.Printf("\x1b[1;33m:: [Security Auditor]\x1b[0m Commencing structural heuristic security validation for \x1b[1;37m%s\x1b[0m...\n", pkgName)
	
	file, err := os.Open(pkgbuildPath)
	if err != nil {
		fmt.Printf("\x1b[1;31m[!] Error:\x1b[0m Unable to open build recipe target for auditing: %v\n", err)
		return false
	}
	defer file.Close()

	totalRiskScore := 0
	var detectedThreats []string
	lineCount := 0

	rules := []HeuristicRule{
		{
			Name:        "Obfuscated Payload Execution",
			Description: "Detects pipe patterns frequently used to execute hidden base64 or encoded payloads.",
			Weight:      WeightObfuscation,
			CheckFn: func(l string) bool {
				return strings.Contains(l, "base64 -d") && (strings.Contains(l, "| sh") || strings.Contains(l, "| bash"))
			},
		},
		{
			Name:        "Dangerous Destructive Patterns",
			Description: "Detects root path deletion threats even when hidden behind environmental variables.",
			Weight:      WeightSystemWipe,
			CheckFn: func(l string) bool {
				return strings.Contains(l, "rm ") && strings.Contains(l, "-rf") && 
					(strings.Contains(l, " /") || strings.Contains(l, "$srcdir/../../") || strings.Contains(l, "chown ") ||
						(strings.Contains(l, "rm -rf /") && !strings.HasPrefix(strings.TrimSpace(l), "#")))
			},
		},
		{
			Name:        "Suspicious Outbound Network Activity",
			Description: "Detects attempts to pipe live raw code from internet endpoints inside the build step.",
			Weight:      WeightNetworkDrop,
			CheckFn: func(l string) bool {
				normalized := strings.ToLower(l)
				return (strings.Contains(normalized, "curl") || strings.Contains(normalized, "wget") || strings.Contains(normalized, "lynx")) && 
					(strings.Contains(normalized, "| bash") || strings.Contains(normalized, "| sh"))
			},
		},
		{
			Name:        "Unauthorized Persistence Injection",
			Description: "Flags attempts to plant user-level background persistence services manually.",
			Weight:      WeightPersistence,
			CheckFn: func(l string) bool {
				return strings.Contains(l, ".service") && strings.Contains(l, "/etc/systemd/")
			},
		},
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lineCount++
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if (strings.Contains(line, "/etc/") || strings.Contains(line, "/usr/bin/") || strings.Contains(line, "/boot/")) && 
			!strings.Contains(line, "$pkgdir") && !strings.Contains(line, "${pkgdir}") {
			detectedThreats = append(detectedThreats, fmt.Sprintf("Line %d: Modification of system root folders outside sandbox", lineCount))
			totalRiskScore += 5
		}

		if strings.Contains(line, "sudo ") || strings.Contains(line, "chmod +x") {
			detectedThreats = append(detectedThreats, fmt.Sprintf("Line %d: Active permissions override or escalation rule", lineCount))
			totalRiskScore += 3
		}

		for _, rule := range rules {
			if rule.CheckFn(line) {
				detectedThreats = append(detectedThreats, fmt.Sprintf("Line %d: [%s] -> %s", lineCount, rule.Name, line))
				totalRiskScore += rule.Weight
			}
		}
	}

	if totalRiskScore == 0 {
		fmt.Println("  \x1b[1;32m✓\x1b[0m Security Audit Passed: No suspicious execution paths or sandbox violations found.")
		return true
	}

	fmt.Printf("\n\x1b[1;31m[!] WARNING: Security Auditor flagged %d potential execution risks:\x1b[0m\n", len(detectedThreats))
	for _, threat := range detectedThreats {
		fmt.Printf("  \x1b[1;33m->\x1b[0m %s\n", threat)
	}

	fmt.Printf("\n\x1b[1;31m[Risk Evaluation Level: %d/100]\x1b[0m\n", totalRiskScore)

	if totalRiskScore >= 50 {
		fmt.Println("\n\x1b[1;31m[CRITICAL]\x1b[0m Package behaviors match signature elements of historical supply-chain attacks. Dropping pipeline.")
		return false
	}

	fmt.Printf("Proceed with native script installation? [y/N]: ")
	var choice string
	fmt.Scanln(&choice)
	choice = strings.ToLower(strings.TrimSpace(choice))
	return choice == "y" || choice == "yes"
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

func isPackageInstalled(pkgName string) bool {
	err := exec.Command("pacman", "-Qi", pkgName).Run()
	return err == nil
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

// UPGRADED FEATURE: Deep Recursive AUR Dependency Graph Installer (Fixed Early Target Skip Bug)
func installFromAUR(pkgName string) {
	fmt.Printf("\x1b[1;32m::\x1b[0m Resolving configuration maps for: '%s'...\n", pkgName)

	apiURL := fmt.Sprintf("https://aur.archlinux.org/rpc/?v=5&type=info&arg[]=%s", pkgName)
	resp, err := http.Get(apiURL)
	if err != nil {
		fmt.Printf("\x1b[1;31mError:\x1b[0m Failed to reach the AUR database API stream: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	var searchData AURSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchData); err != nil || searchData.ResultCount == 0 {
		fmt.Printf("\x1b[1;31mError:\x1b[0m Package '%s' does not exist in the AUR database records.\n", pkgName)
		os.Exit(1)
	}

	targetPkg := searchData.Results[0]
	repoTarget := targetPkg.PackageBase
	if repoTarget == "" {
		repoTarget = targetPkg.Name
	}

	// Dynamic dependency engine processing loop (only skips dependency targets that are installed)
	allDeps := append(targetPkg.Depends, targetPkg.MakeDepends...)
	for _, dep := range allDeps {
		cleanDep := strings.FieldsFunc(dep, func(r rune) bool {
			return r == '>' || r == '=' || r == '<'
		})[0]

		if !isPackageInstalled(cleanDep) {
			isOfficial := exec.Command("pacman", "-Si", cleanDep).Run() == nil
			if !isOfficial {
				fmt.Printf("\x1b[1;33m-> Found unfulfilled AUR dependency:\x1b[0m %s. Resolving recursively...\n", cleanDep)
				installFromAUR(cleanDep) 
			}
		}
	}

	cacheDir := filepath.Join(os.Getenv("HOME"), ".cache/superinstall", repoTarget)
	_ = os.MkdirAll(filepath.Join(os.Getenv("HOME"), ".cache/superinstall"), 0755)
	_ = os.RemoveAll(cacheDir)

	fmt.Printf("\x1b[1;34m->\x1b[0m Cloning source tree from: https://aur.archlinux.org/%s.git\n", repoTarget)
	cloneCmd := exec.Command("git", "clone", "https://aur.archlinux.org/"+repoTarget+".git", cacheDir)
	cloneCmd.Stdout = os.Stdout
	cloneCmd.Stderr = os.Stderr
	if err := cloneCmd.Run(); err != nil {
		fmt.Printf("\x1b[1;31mError:\x1b[0m Failed to pull git source mapping for packaging.\n")
		os.Exit(1)
	}

	pkgbuildPath := filepath.Join(cacheDir, "PKGBUILD")
	
	if _, err := os.Stat(pkgbuildPath); os.IsNotExist(err) {
		fmt.Printf("\x1b[1;31mError:\x1b[0m The repository for '%s' cloned successfully but contains no PKGBUILD recipe.\n", pkgName)
		os.Exit(1)
	}

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

// FEATURE: Full Native and AUR Hybrid Upgrade Sequence (-Syu)
func executeFullSystemUpgrade() {
	fmt.Println("\x1b[1;32m:: Synchronizing core pacman database repositories...\x1b[0m")
	executePacmanCmd("-Syu")

	fmt.Println("\n\x1b[1;34m:: Initiating deep structural query for local AUR upgrades...\x1b[0m")
	
	out, err := exec.Command("pacman", "-Qm").Output()
	if err != nil {
		fmt.Println("Notice: No locally compiled foreign repository packages located.")
		return
	}

	lines := strings.Split(string(out), "\n")
	var targets []string
	var upgradeList []LocalAURPackage

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		targets = append(targets, fields[0])
	}

	if len(targets) == 0 {
		fmt.Println("All tracking packages are completely up to date.")
		return
	}

	// Batch verify via live AUR API requests
	for _, pkgName := range targets {
		apiURL := fmt.Sprintf("https://aur.archlinux.org/rpc/?v=5&type=info&arg[]=%s", pkgName)
		resp, err := http.Get(apiURL)
		if err != nil {
			continue
		}
		
		var searchData AURSearchResponse
		if err := json.NewDecoder(resp.Body).Decode(&searchData); err == nil && searchData.ResultCount > 0 {
			remoteVer := searchData.Results[0].Version
			
			localOut, _ := exec.Command("pacman", "-Q", pkgName).Output()
			localFields := strings.Fields(string(localOut))
			if len(localFields) >= 2 {
				localVer := localFields[1]
				if localVer != remoteVer {
					upgradeList = append(upgradeList, LocalAURPackage{
						Name:          pkgName,
						LocalVersion:  localVer,
						RemoteVersion: remoteVer,
					})
				}
			}
		}
		resp.Body.Close()
	}

	if len(upgradeList) == 0 {
		fmt.Println("\x1b[1;32m✓ Foreign AUR repositories match current upstream development trees.\x1b[0m")
		return
	}

	fmt.Printf("\n\x1b[1;33m:: %d Foreign track packages out of sync. Upgrading targets:\x1b[0m\n", len(upgradeList))
	for _, item := range upgradeList {
		fmt.Printf("  \x1b[1;35maur/\x1b[1;37m%s\x1b[0m [\x1b[1;31m%s\x1b[0m -> \x1b[1;32m%s\x1b[0m]\n", item.Name, item.LocalVersion, item.RemoteVersion)
	}

	fmt.Print("\nCommence execution matrix compilation? [Y/n]: ")
	var answer string
	fmt.Scanln(&answer)
	answer = strings.ToLower(strings.TrimSpace(answer))
	
	if answer == "" || answer == "y" || answer == "yes" {
		for _, item := range upgradeList {
			fmt.Printf("\n\x1b[1;32m-> Triggering deployment pipeline for:\x1b[0m %s\n", item.Name)
			installFromAUR(item.Name)
		}
	}
}

func installSelf() {
	fmt.Println("\x1b[1;32m::\x1b[0m Initiating superinstall core self-compilation deployment...")
	homeDir, _ := os.UserHomeDir()
	binDir := filepath.Join(homeDir, ".local/bin")
	_ = os.MkdirAll(binDir, 0755)

	targetBinaryPath := filepath.Join(binDir, "superinstall")
	fmt.Println("\x1b[1;34m->\x1b[0m Compiling production runtime optimized binaries...")
	
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
	if len(os.Args) > 1 {
		if os.Args[1] == "???" {
			printEasterEggLogo()
			return
		}
		if os.Args[1] == "????" {
			printEntireSourceCode()
			return
		}
	}

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
		executeFullSystemUpgrade() 
		return
	case "-search":
		if len(os.Args) > 2 {
			searchAUR(os.Args[2])
		} else {
			fmt.Println("Error: Missing query string parameters.")
		}
		return
	case "-S": // FIX: Explicit switch branch captures `-S` correctly instead of short-circuiting downstream
		if len(os.Args) > 2 {
			pkg := os.Args[2]
			_, exists := RepoMapping[pkg]
			if !exists {
				installFromAUR(pkg)
			} else {
				mprRoot := filepath.Join(os.Getenv("HOME"), ".local/share/superinstall")
				fmt.Printf("[Target Discovery] Host System: %s (%s)\n", runtime.GOOS, runtime.GOARCH)
				fmt.Printf("Handling index deployment sequence for quick target lookup: %s in %s\n", pkg, mprRoot)
			}
		} else {
			fmt.Println("Error: Missing package target specification.")
		}
		return
	}

	// Fallback mechanism to handle raw arguments without flags
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

func RunSecurityAudit(pkgName string, pkgbuildPath string) bool {
	return runSecurityAudit(pkgName, pkgbuildPath)
}

func printEasterEggLogo() {
	logo := `
  ____  _   ...       _all!       /\
 / ___|| | | (_)_ __  ___| |_        /  \
 \___ \| | | | | '_ \/ __| __|      /____\
  ___) | |_| | | | | \__ \ |_       |    |
 |____/ \___/|_|_| |_|___/\__|      | \/ |
                                    |____|
`
	fmt.Println(logo)
}

func printEntireSourceCode() {
	files := []string{
		"go.mod",
		"main.go",
		"providers/aur.go",
		"providers/providers.go",
	}

	fmt.Println("==================================================")
	fmt.Println("   SUPERINSTALL SYSTEM BLUEPRINT (TOTAL DUMP)     ")
	fmt.Println("==================================================")

	for _, fileName := range files {
		data, err := sourceFiles.ReadFile(fileName)
		if err != nil {
			continue
		}
		fmt.Printf("\n--- FILE: %s ---\n", fileName)
		fmt.Println(string(data))
		fmt.Println("--------------------------------------------------")
	}
}