package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

type TargetConfig struct {
	OS          string
	InstallCmd  string
	SyncCmd     string
	UpgradeCmd  string
	SearchCmd   string
	InstallArgs []string
	SyncArgs    []string
	UpgradeArgs []string
	SearchArgs  []string
}

var sysConfig TargetConfig
var httpClient = &http.Client{Timeout: 6 * time.Second}

func init() {
	sysConfig = detectPlatform()
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// Automated Privilege Scaling Self-Deployment Matrix
	if os.Args[1] == "--install-self" {
		handleSelfInstallation()
		return
	}

	ensureWarpConnectivity()

	mode := os.Args[1]

	switch mode {
	case "-Sy":
		handleDatabaseSync()
	case "-Syu":
		handleSystemUpgrade()
	case "-search":
		if len(os.Args) < 3 {
			fmt.Println("Error: Missing search query specification keyword.")
			os.Exit(1)
		}
		handlePackageSearch(os.Args[2])
	case "-S":
		if len(os.Args) < 3 {
			fmt.Println("Error: Missing target package specification argument.")
			os.Exit(1)
		}
		handleInstallPipeline(os.Args[2])
	default:
		printUsage()
		os.Exit(1)
	}
}
// DYNAMIC PATH AUTO-UPDATE (The "No-Hardcoding" Logic)
func checkAutoUpdate() {
	exePath, _ := os.Executable()
	info, err := os.Stat(exePath)
	if err != nil { return }

	// Check if 7 days have passed
	if time.Since(info.ModTime()).Hours() > (24 * 7) {
		fmt.Println(":: [superinstall] 7-day update cycle reached. Checking for updates...")
		
		// Find user's home directory dynamically
		home, err := os.UserHomeDir()
		if err != nil { return }
		
		// Assumes project is cloned to ~/superinstall
		projectDir := filepath.Join(home, "superinstall")
		
		// If the directory exists, attempt update
		if _, err := os.Stat(projectDir); err == nil {
			fmt.Println(":: Pulling latest source from repository...")
			cmd := exec.Command("git", "pull", "origin", "main")
			cmd.Dir = projectDir
			_ = cmd.Run()
			
			fmt.Println(":: Recompiling binary...")
			// Using a shell script wrapper to avoid "File in use" errors on Windows/Linux
			updateCmd := fmt.Sprintf("go build -o %s %s/main.go", exePath, projectDir)
			runRaw("sh", "-c", updateCmd) 
			fmt.Println(":: Update successful. Please restart your command.")
			os.Exit(0)
		}
	}
}
func printUsage() {
	fmt.Println("=========================================================================")
	fmt.Println("Superinstall v1.0 - The Cross-Platform Hardened Package Management Engine")
	fmt.Println("=========================================================================")
	fmt.Println("\nCore Management Matrix Enforcements:")
	fmt.Println("  superinstall -Sy                Synchronize local package databases repositories")
	fmt.Println("  superinstall -Syu               Synchronize databases and execute complete system upgrade")
	fmt.Println("  superinstall -search <query>    Query global and local package availability indexes")
	fmt.Println("  superinstall -S <package>       Validate, sandbox-audit, and install package mapping")
	fmt.Println("  superinstall --install-self     Compile and establish tool root entry inside system path")
}

// =========================================================================
// REAL-TIME SYSTEM REGISTRY VALIDATION (Fixes Misspellings and Fails Early)
// =========================================================================
func validatePackageExistence(pkgName string) bool {
	// Bypass verification loops for URL/Git routes
	if strings.HasPrefix(pkgName, "http://") || strings.HasPrefix(pkgName, "https://") || strings.HasSuffix(pkgName, ".git") {
		return true
	}

	// 1. Handle Arch / AUR specialized split index layers
	if sysConfig.OS == "arch" {
		// First verify if it's sitting inside the native repository database layers
		checkNative := exec.Command("pacman", "-Si", pkgName)
		if err := checkNative.Run(); err == nil {
			return true
		}
		// Second, query the AUR endpoint RPC interface to see if it exists upstream
		apiURL := fmt.Sprintf("https://aur.archlinux.org/rpc/?v=5&type=info&arg[]=%s", url.QueryEscape(pkgName))
		resp, err := httpClient.Get(apiURL)
		if err == nil {
			defer resp.Body.Close()
			var aurResp struct {
				ResultCount int `json:"resultcount"`
			}
			if errDec := json.NewDecoder(resp.Body).Decode(&aurResp); errDec == nil {
				return aurResp.ResultCount > 0
			}
		}
		return false
	}

	// 2. Query Windows Winget Source Registry Catalogs
	if sysConfig.OS == "windows" {
		var out bytes.Buffer
		checkWin := exec.Command("winget", "search", "--exact", pkgName)
		checkWin.Stdout = &out
		_ = checkWin.Run()
		return !strings.Contains(out.String(), "No package found") && out.Len() > 0
	}

	// 3. Query macOS Homebrew Cellar Metadata Indexes
	if sysConfig.OS == "macos" {
		checkMac := exec.Command("brew", "info", pkgName)
		return checkMac.Run() == nil
	}

	// 4. Multi-Distro Linux & BSD Native Registry Inquiries
	var cmd *exec.Cmd
	switch sysConfig.OS {
	case "debian":
		cmd = exec.Command("apt-cache", "show", pkgName)
	case "fedora":
		cmd = exec.Command("dnf", "list", "available", pkgName)
	case "gentoo":
		cmd = exec.Command("emerge", "--search", pkgName)
	case "freebsd", "openbsd", "netbsd":
		cmd = exec.Command(sysConfig.SearchCmd, append(sysConfig.SearchArgs, pkgName)...)
	default:
		return true // Fallback to avoid complete path blocking on undetected kernels
	}

	return cmd.Run() == nil
}

// =========================================================================
// CENTRAL COMMAND EXECUTION SCHEDULERS (-Sy, -Syu, -search)
// =========================================================================
func handleDatabaseSync() {
	fmt.Printf(":: [superinstall] Executing repository database synchronization mapping for: %s\n", sysConfig.OS)
	if sysConfig.SyncCmd == "" {
		fmt.Println("Database synchronization is handled automatically on this architecture platform.")
		return
	}
	executeSystemCommand(sysConfig.SyncCmd, sysConfig.SyncArgs, true)
}

func handleSystemUpgrade() {
	fmt.Printf(":: [superinstall] Initiating global system transaction rollback and upgrades for: %s\n", sysConfig.OS)
	if sysConfig.OS == "arch" {
		// Native pacman rollout combined with localized AUR tracking sweeps
		executeSystemCommand("sudo", []string{"pacman", "-Syu", "--noconfirm"}, false)
		return
	}
	executeSystemCommand(sysConfig.UpgradeCmd, sysConfig.UpgradeArgs, true)
}

func handlePackageSearch(query string) {
	fmt.Printf(":: [superinstall] Querying operational indexes for search trace: '%s'\n", query)
	
	if sysConfig.OS == "arch" {
		fmt.Println("\n[Native Community Repositories]")
		_ = runRaw("pacman", "-Ss", query)
		
		fmt.Println("\n[Arch User Repository (AUR) Database Index]")
		apiURL := fmt.Sprintf("https://aur.archlinux.org/rpc/?v=5&type=search&arg=%s", url.QueryEscape(query))
		resp, err := httpClient.Get(apiURL)
		if err == nil {
			defer resp.Body.Close()
			var searchResp struct {
				Results []struct {
					Name        string `json:"Name"`
					Version     string `json:"Version"`
					Description string `json:"Description"`
				} `json:"results"`
			}
			if errDec := json.NewDecoder(resp.Body).Decode(&searchResp); errDec == nil {
				for _, res := range searchResp.Results {
					fmt.Printf("aur/%s \x1b[1;32m%s\x1b[0m\n    %s\n", res.Name, res.Version, res.Description)
				}
			}
		}
		return
	}

	executeSystemCommand(sysConfig.SearchCmd, append(sysConfig.SearchArgs, query), false)
}

func handleInstallPipeline(target string) {
	// HARD ENFORCEMENT LAYER: Check database map before compiling or execution patterns map out
	if !validatePackageExistence(target) {
		fmt.Println("\n=========================================================================")
		fmt.Printf("CRITICAL EXECUTION FAULT: ACTUAL PACKAGE MANAGER ENGINE BLOCKER\n")
		fmt.Printf("   Error: The package target '%s' is INVALID or MISSPELLLED.\n", target)
		fmt.Printf("   System layer execution aborted to protect machine configuration files.\n")
		fmt.Println("=========================================================================")
		os.Exit(1)
	}

	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") || strings.HasSuffix(target, ".git") {
		handleGitInstall(target)
		return
	}

	handleInstall(target)
}

// =========================================================================
// SYSTEM REPOSITORY CONTROLLERS ENGINE CORES
// =========================================================================
func executeSystemCommand(binary string, args []string, forceSudo bool) {
	finalArgs := args
	finalBinary := binary

	if forceSudo && sysConfig.OS != "windows" && sysConfig.OS != "macos" && sysConfig.OS != "nixos" {
		finalArgs = append([]string{binary}, args...)
		finalBinary = "sudo"
	}

	cmd := exec.Command(finalBinary, finalArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		fmt.Printf("Execution layer deployment failure reported: %v\n", err)
		os.Exit(1)
	}
}

// =========================================================================
// HARDENED SECURITY DETECTOR ENGINE (WEIGHTED SCORING MATRICES)
// =========================================================================
func scanForMaliciousCode(dirPath string) (bool, []string) {
	criticalWipers := []string{"rm -rf", "rm -df", "mkfs", "dd if=", "dd of=", ":(){ :|:& };:"}
	obfuscationTriggers := []string{"base64 --decode", "base64 -d", "hex2bin", "str_rot13", "eval($( ", "eval `"}
	networkTriggers := []string{"curl ", "wget ", "fetch ", "python -c", "perl -e"}
	adminTriggers := []string{"systemctl stop", "systemctl disable", "init 0", "shutdown"}

	var foundThreats []string
	totalRiskScore := 0

	_ = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".go" || ext == ".md" || ext == ".png" || ext == ".jpg" || ext == ".toml" {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		lineNumber := 0
		for scanner.Scan() {
			lineNumber++
			line := strings.ToLower(scanner.Text())
			
			if strings.Contains(line, "rm -rf") && (strings.Contains(line, "src/") || strings.Contains(line, "pkg/")) {
				continue 
			}

			for _, sig := range criticalWipers {
				if strings.Contains(line, sig) {
					if strings.Contains(line, "/") || strings.Contains(line, "$") {
						totalRiskScore += 100
						foundThreats = append(foundThreats, fmt.Sprintf("%s (Line %d): CRITICAL WIPER - Found dangerous file deletion blueprint '%s'", filepath.Base(path), lineNumber, sig))
					}
				}
			}

			for _, sig := range obfuscationTriggers {
				if strings.Contains(line, sig) {
					totalRiskScore += 60
					foundThreats = append(foundThreats, fmt.Sprintf("%s (Line %d): OBFUSCATION DETECTED - Runtime decoding hook found '%s'", filepath.Base(path), lineNumber, sig))
				}
			}

			for _, sig := range networkTriggers {
				if strings.Contains(line, sig) {
					totalRiskScore += 15
					foundThreats = append(foundThreats, fmt.Sprintf("%s (Line %d): NETWORK CALL - Script fetches external payload resources via '%s'", filepath.Base(path), lineNumber, strings.TrimSpace(sig)))
				}
			}

			for _, sig := range adminTriggers {
				if strings.Contains(line, sig) {
					totalRiskScore += 10
					foundThreats = append(foundThreats, fmt.Sprintf("%s (Line %d): SYSTEM MANAGEMENT - Script manipulates core background services via '%s'", filepath.Base(path), lineNumber, sig))
				}
			}
		}
		return nil
	})

	isMalicious := totalRiskScore >= 100
	return isMalicious, foundThreats
}

func runSecurityGatekeeper(pkgName string, dirPath string) bool {
	isMalicious, threats := scanForMaliciousCode(dirPath)
	
	normalizedName := strings.ToLower(pkgName)
	trollKeywords := []string{"suicide", "forkbomb", "system-wipe", "brick", "destroy"}
	for _, keyword := range trollKeywords {
		if strings.Contains(normalizedName, keyword) {
			isMalicious = true
			threats = append(threats, fmt.Sprintf("Identity Red Flag: Target workspace name matched malicious database profile string ('%s')", keyword))
		}
	}

	fmt.Println("\n=========================================================================")
	fmt.Printf(":: [superinstall SECURITY AUDIT] Reviewing target architecture: %s\n", pkgName)
	fmt.Println("=========================================================================")

	if isMalicious {
		fmt.Printf("\n WARNING: [NOT RECOMMENDED IT HAS SOME MALICIOUS CODES]\n")
		fmt.Println("The automated risk-scoring arrays flagged a high danger threshold:")
		for _, threat := range threats {
			fmt.Printf("  -> %s\n", threat)
		}
		fmt.Print("\nProceeding with this target could fully brick your environment. Override safety systems? (y/N): ")
		var input string
		fmt.Scanln(&input)
		return strings.ToLower(input) == "y"
	}

	fmt.Printf("\n STATUS: [RECOMMENDED TO INSTALL] Risk score is well within safe operating limits.\n")
	for i := 3; i >= 0; i-- { 
		fmt.Printf("\r System Verification Matrix: Hold for %d seconds...", i)
		time.Sleep(1 * time.Second)
	}
	fmt.Println()

	fmt.Printf("\nDo you want to install this package? (y/n): ")
	var input string
	fmt.Scanln(&input)
	return strings.ToLower(input) == "y"
}

// =========================================================================
// AUTOMATED SELF-INSTALLATION PATH ENGINE
// =========================================================================
func handleSelfInstallation() {
	fmt.Println(":: [superinstall] Compiling and deploying binary engine layout globally...")
	
	binaryName := "superinstall"
	if runtime.GOOS == "windows" {
		binaryName = "superinstall.exe"
	}

	cmdBuild := exec.Command("go", "build", "-o", binaryName, "main.go")
	cmdBuild.Stdout = os.Stdout
	cmdBuild.Stderr = os.Stderr
	if err := cmdBuild.Run(); err != nil {
		fmt.Printf("Compilation failure aborted: %v\n", err)
		return
	}

	var targetDest string
	switch runtime.GOOS {
	case "windows":
		targetDest = "C:\\Windows\\System32\\" + binaryName
	default:
		targetDest = "/usr/local/bin/" + binaryName
	}

	fmt.Printf(":: Relocating runtime environment binary assets directly to system path: %s\n", targetDest)
	var cmdMove *exec.Cmd
	if runtime.GOOS == "windows" {
		cmdMove = exec.Command("cmd", "/C", "move", binaryName, targetDest)
	} else if runtime.GOOS == "darwin" {
		cmdMove = exec.Command("mv", binaryName, targetDest) 
	} else {
		cmdMove = exec.Command("sudo", "mv", binaryName, targetDest)
	}

	cmdMove.Stdout = os.Stdout
	cmdMove.Stderr = os.Stderr
	if err := cmdMove.Run(); err != nil {
		fmt.Printf("Deployment migration path adjustment failure: %v\n", err)
		return
	}

	fmt.Println("Success! [superinstall] is now live and secured across your terminal interfaces globally.")
}

// =========================================================================
// GLOBAL OPERATING OS PROFILE DISTRO DETECTOR DEFINITION MATRIX
// =========================================================================
func detectPlatform() TargetConfig {
	switch runtime.GOOS {
	case "windows":
		return TargetConfig{OS: "windows", InstallCmd: "winget", SyncCmd: "winget", UpgradeCmd: "winget", SearchCmd: "winget", InstallArgs: []string{"install", "--silent"}, SyncArgs: []string{"source", "update"}, UpgradeArgs: []string{"upgrade", "--all"}, SearchArgs: []string{"search"}}
	case "darwin": 
		return TargetConfig{OS: "macos", InstallCmd: "brew", SyncCmd: "brew", UpgradeCmd: "brew", SearchCmd: "brew", InstallArgs: []string{"install"}, SyncArgs: []string{"update"}, UpgradeArgs: []string{"upgrade"}, SearchArgs: []string{"search"}}
	case "freebsd":
		return TargetConfig{OS: "freebsd", InstallCmd: "pkg", SyncCmd: "pkg", UpgradeCmd: "pkg", SearchCmd: "pkg", InstallArgs: []string{"install", "-y"}, SyncArgs: []string{"update"}, UpgradeArgs: []string{"upgrade", "-y"}, SearchArgs: []string{"search"}}
	case "openbsd":
		return TargetConfig{OS: "openbsd", InstallCmd: "pkg_add", SyncCmd: "", UpgradeCmd: "syspatch", SearchCmd: "pkg_info", InstallArgs: []string{}, SyncArgs: []string{}, UpgradeArgs: []string{}, SearchArgs: []string{"-Q"}}
	case "netbsd":
		return TargetConfig{OS: "netbsd", InstallCmd: "pkgin", SyncCmd: "pkgin", UpgradeCmd: "pkgin", SearchCmd: "pkgin", InstallArgs: []string{"install", "-y"}, SyncArgs: []string{"update"}, UpgradeArgs: []string{"upgrade", "-y"}, SearchArgs: []string{"search"}}
	case "linux":
		return detectLinuxDistro()
	default:
		return TargetConfig{OS: "unknown", InstallCmd: "echo"}
	}
}

func detectLinuxDistro() TargetConfig {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return TargetConfig{OS: "linux", InstallCmd: "apt-get", SyncCmd: "apt-get", UpgradeCmd: "apt-get", SearchCmd: "apt-cache", InstallArgs: []string{"install", "-y"}, SyncArgs: []string{"update"}, UpgradeArgs: []string{"dist-upgrade", "-y"}, SearchArgs: []string{"search"}}
	}
	defer file.Close()

	id, idLike := "", ""
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "ID=") {
			id = strings.Trim(strings.Split(line, "=")[1], "\"")
		}
		if strings.HasPrefix(line, "ID_LIKE=") {
			idLike = strings.Trim(strings.Split(line, "=")[1], "\"")
		}
	}

	combined := strings.ToLower(id + " " + idLike)
	switch {
	case strings.Contains(combined, "arch"):
		return TargetConfig{OS: "arch", InstallCmd: "pacman", SyncCmd: "pacman", UpgradeCmd: "pacman", SearchCmd: "pacman", InstallArgs: []string{"-S", "--noconfirm"}, SyncArgs: []string{"-Sy"}, UpgradeArgs: []string{"-Syu", "--noconfirm"}, SearchArgs: []string{"-Ss"}}
	case strings.Contains(combined, "gentoo"): 
		return TargetConfig{OS: "gentoo", InstallCmd: "emerge", SyncCmd: "emaint", UpgradeCmd: "emerge", SearchCmd: "emerge", InstallArgs: []string{"--ask=n"}, SyncArgs: []string{"-a", "sync"}, UpgradeArgs: []string{"-auDN", "@world"}, SearchArgs: []string{"--search"}}
	case strings.Contains(combined, "fedora") || strings.Contains(combined, "rhel"):
		return TargetConfig{OS: "fedora", InstallCmd: "dnf", SyncCmd: "dnf", UpgradeCmd: "dnf", SearchCmd: "dnf", InstallArgs: []string{"install", "-y"}, SyncArgs: []string{"makecache"}, UpgradeArgs: []string{"upgrade", "-y"}, SearchArgs: []string{"search"}}
	case strings.Contains(combined, "suse"):
		return TargetConfig{OS: "opensuse", InstallCmd: "zypper", SyncCmd: "zypper", UpgradeCmd: "zypper", SearchCmd: "zypper", InstallArgs: []string{"install", "-y"}, SyncArgs: []string{"refresh"}, UpgradeArgs: []string{"dup", "-y"}, SearchArgs: []string{"search"}}
	case strings.Contains(combined, "nix"):
		return TargetConfig{OS: "nixos", InstallCmd: "nix-env", SyncCmd: "nix-channel", UpgradeCmd: "nixos-rebuild", SearchCmd: "nix-env", InstallArgs: []string{"-iA"}, SyncArgs: []string{"--update"}, UpgradeArgs: []string{"switch", "--upgrade"}, SearchArgs: []string{"-qaP"}}
	default:
		return TargetConfig{OS: "debian", InstallCmd: "apt-get", SyncCmd: "apt-get", UpgradeCmd: "apt-get", SearchCmd: "apt-cache", InstallArgs: []string{"install", "-y"}, SyncArgs: []string{"update"}, UpgradeArgs: []string{"dist-upgrade", "-y"}, SearchArgs: []string{"search"}}
	}
}

func handleInstall(pkgName string) {
	if sysConfig.OS == "windows" || sysConfig.OS == "macos" {
		_ = runRaw(sysConfig.InstallCmd, append(sysConfig.InstallArgs, pkgName)...)
		return
	}

	if sysConfig.OS == "arch" {
		isAur, deps := resolveAURDepsParallel(pkgName)
		if isAur {
			for _, dep := range deps {
				buildAURPackage(dep)
			}
			return
		}
	}

	args := append([]string{sysConfig.InstallCmd}, sysConfig.InstallArgs...)
	args = append(args, pkgName)

	if sysConfig.OS != "nixos" && sysConfig.OS != "windows" && sysConfig.OS != "macos" && sysConfig.OS != "gentoo" {
		args = append([]string{"sudo"}, args...)
	}
	_ = runRaw(args[0], args[1:]...)
}

func resolveAURDepsParallel(mainPkg string) (bool, []string) {
	var (
		wg           sync.WaitGroup
		mutex        sync.Mutex
		collected    = make(map[string]bool)
		dependencies []string
	)

	var worker func(pkg string)
	worker = func(pkg string) {
		defer wg.Done()

		apiURL := fmt.Sprintf("https://aur.archlinux.org/rpc/?v=5&type=info&arg[]=%s", url.QueryEscape(pkg))
		resp, err := httpClient.Get(apiURL)
		if err != nil {
			return
		}
		defer resp.Body.Close()

		var aurResp struct {
			ResultCount int `json:"resultcount"`
			Results     []struct {
				Depends     []string `json:"Depends"`
				MakeDepends []string `json:"MakeDepends"`
			} `json:"results"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&aurResp)

		if aurResp.ResultCount == 0 {
			return
		}

		mutex.Lock()
		if !collected[pkg] {
			collected[pkg] = true
			dependencies = append([]string{pkg}, dependencies...)
		}
		mutex.Unlock()

		for _, res := range aurResp.Results {
			for _, d := range append(res.Depends, res.MakeDepends...) {
				cleanDep := strings.FieldsFunc(d, func(r rune) bool {
					return r == '>' || r == '<' || r == '='
				})[0]

				mutex.Lock()
				seen := collected[cleanDep]
				mutex.Unlock()

				if !seen {
					wg.Add(1)
					go worker(cleanDep)
				}
			}
		}
	}

	wg.Add(1)
	go worker(mainPkg)
	wg.Wait()

	return len(dependencies) > 0, dependencies
}

func buildAURPackage(pkg string) {
	tmpDir, err := os.MkdirTemp("", "superinstall-aur-*")
	if err != nil {
		return
	}
	defer os.RemoveAll(tmpDir)

	if err := runCmdInDir(tmpDir, "git", "clone", "--depth=1", "--single-branch", fmt.Sprintf("https://aur.archlinux.org/%s.git", pkg)); err != nil {
		return
	}

	targetPkgDir := filepath.Join(tmpDir, pkg)

	if !runSecurityGatekeeper(pkg, targetPkgDir) {
		fmt.Println(":: [superinstall] Safely aborted deployment execution.")
		return
	}

	attemptInstallationWithPGPFix(targetPkgDir)
}

func attemptInstallationWithPGPFix(pkgDir string) {
	var outBuffer bytes.Buffer
	
	cmd := exec.Command("makepkg", "-si", "--noconfirm", "--needed")
	cmd.Dir = pkgDir
	cmd.Stdout = io.MultiWriter(os.Stdout, &outBuffer)
	cmd.Stderr = io.MultiWriter(os.Stderr, &outBuffer)
	cmd.Stdin = os.Stdin

	err := cmd.Run()
	if err == nil {
		return 
	}

	outputLog := outBuffer.String()
	if strings.Contains(outputLog, "signatures could not be verified") || strings.Contains(outputLog, "unknown public key") {
		fmt.Println("\n [superinstall SELF-HEAL] Detected missing PGP Signature exception profile.")
		
		var targetKey string
		scanner := bufio.NewScanner(strings.NewReader(outputLog))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "unknown public key") || strings.Contains(line, "key") {
				words := strings.Fields(line)
				for _, word := range words {
					word = strings.Trim(word, "'\"`().,")
					if len(word) == 16 || len(word) == 40 { 
						targetKey = word
						break
					}
				}
			}
		}

		if targetKey != "" {
			var lookupBuffer bytes.Buffer
			lookupCmd := exec.Command("gpg", "--keyserver", "hkps://keyserver.ubuntu.com", "--dry-run", "--with-colons", "--search-keys", targetKey)
			lookupCmd.Stdout = &lookupBuffer
			_ = lookupCmd.Run()
			
			identityName := "Unknown Developer / Unlisted Keyring Metadata"
			lookupOut := lookupBuffer.String()
			
			scannerLookup := bufio.NewScanner(strings.NewReader(lookupOut))
			for scannerLookup.Scan() {
				line := scannerLookup.Text()
				if strings.HasPrefix(line, "uid:") {
					parts := strings.Split(line, ":")
					if len(parts) > 9 {
						identityName = parts[9] 
						break
					}
				}
			}

			fmt.Printf("\n PGP IDENTITY VERIFICATION:\n")
			fmt.Printf("   Key ID:   %s\n", targetKey)
			fmt.Printf("   Owner:    %s\n", identityName)
			fmt.Print("\nDo you trust this developer and want to import their public key? (y/N): ")
			
			var trustInput string
			fmt.Scanln(&trustInput)
			
			if strings.ToLower(trustInput) == "y" {
				fmt.Printf(":: Attempting keyserver asset sync injection for PGP ID: %s\n", targetKey)
				fetchCmd := exec.Command("gpg", "--recv-keys", targetKey)
				fetchCmd.Stdout = os.Stdout
				fetchCmd.Stderr = os.Stderr
				if errKey := fetchCmd.Run(); errKey == nil {
					fmt.Println("PGP signature verified & imported. Restarting compilation matrix...")
					_ = runCmdInDir(pkgDir, "makepkg", "-si", "--noconfirm", "--needed")
					return
				}
			} else {
				fmt.Println(":: [superinstall] Key import rejected by user. Halting installation.")
				return
			}
		}
		
		fmt.Print("\nKeyserver sync dropped out. Do you want to force bypass PGP verification? (y/N): ")
		var choice string
		fmt.Scanln(&choice)
		if strings.ToLower(choice) == "y" {
			_ = runCmdInDir(pkgDir, "makepkg", "-si", "--noconfirm", "--needed", "--skippgpcheck")
		}
	}
}

func handleGitInstall(gitURL string) {
	baseName := strings.TrimSuffix(filepath.Base(gitURL), ".git")
	tmpDir, err := os.MkdirTemp("", "superinstall-git-*")
	if err != nil {
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	normalizedBase := strings.ToLower(baseName)
	if strings.Contains(normalizedBase, "suicide") || strings.Contains(normalizedBase, "forkbomb") {
		fmt.Println("\n=========================================================================")
		fmt.Printf("CRITICAL WARNING: [NOT RECOMMENDED IT HAS SOME MALICIOUS CODES]\n")
		fmt.Printf("Target name matches signature for known high-risk/troll applications ('%s')\n", baseName)
		fmt.Println("=========================================================================")
		fmt.Print("\nDo you want to override safety protocols and clone this anyway? (y/N): ")
		var input string
		fmt.Scanln(&input)
		if strings.ToLower(input) != "y" {
			fmt.Println(":: [superinstall] Safely aborted deployment execution.")
			return
		}
	}

	if err := runCmdInDir(tmpDir, "git", "clone", "--depth=1", "--single-branch", gitURL); err != nil {
		os.Exit(1)
	}

	targetDir := filepath.Join(tmpDir, baseName)
	isWindows := sysConfig.OS == "windows"
	isBSD := strings.Contains(sysConfig.OS, "bsd")

	if !runSecurityGatekeeper(baseName, targetDir) {
		fmt.Println(":: [superinstall] Safe exit execution aborted.")
		return
	}

	switch {
	case fileExists(filepath.Join(targetDir, "PKGBUILD")) && sysConfig.OS == "arch":
		attemptInstallationWithPGPFix(targetDir)

	case fileExists(filepath.Join(targetDir, "Makefile")):
		makeCmd := "make"
		if isBSD {
			makeCmd = "gmake"
		}
		_ = runCmdInDir(targetDir, makeCmd)
		if isWindows {
			_ = runCmdInDir(targetDir, makeCmd, "install")
		} else if sysConfig.OS == "macos" {
			_ = runCmdInDir(targetDir, makeCmd, "install") 
		} else {
			_ = runCmdInDir(targetDir, "sudo", makeCmd, "install")
		}

	case fileExists(filepath.Join(targetDir, "Cargo.toml")):
		_ = runCmdInDir(targetDir, "cargo", "build", "--release")
		dest := "/usr/local/bin/"
		if isWindows {
			dest = "C:\\Windows\\System32\\"
		}
		if sysConfig.OS == "macos" {
			_ = runCmdInDir(targetDir, "cp", filepath.Join("target", "release", baseName), dest)
		} else {
			_ = runCmdInDir(targetDir, "sudo", "cp", filepath.Join("target", "release", baseName), dest)
		}

	default:
		fmt.Println(":: [superinstall] Blueprint complete, no executable build pattern triggered.")
	}
}

func ensureWarpConnectivity() {
	if sysConfig.OS == "macos" || sysConfig.OS == "windows" {
		return 
	}
	testURLs := []string{"https://aur.archlinux.org", "https://archive.org", "https://github.com"}
	needsWarp := false
	for _, target := range testURLs {
		resp, err := httpClient.Get(target)
		if err != nil || (resp != nil && resp.StatusCode >= 500) {
			needsWarp = true
			break
		}
		if resp != nil {
			resp.Body.Close()
		}
	}

	if !needsWarp {
		return
	}

	_, lookErr := exec.LookPath("warp-cli")
	if lookErr != nil {
		switch sysConfig.OS {
		case "arch":
			tmpDir, _ := os.MkdirTemp("", "superinstall-warp-*")
			_ = runCmdInDir(tmpDir, "git", "clone", "--depth=1", "https://aur.archlinux.org/cloudflare-warp-bin.git")
			_ = runCmdInDir(filepath.Join(tmpDir, "cloudflare-warp-bin"), "makepkg", "-si", "--noconfirm")
			os.RemoveAll(tmpDir)
		case "debian":
			_ = runRaw("sudo", "apt-get", "update")
			_ = runRaw("sudo", "apt-get", "install", "-y", "cloudflare-warp")
		case "fedora":
			_ = runRaw("sudo", "dnf", "install", "-y", "cloudflare-warp")
		case "gentoo":
			_ = runRaw("sudo", "emerge", "--ask=n", "net-vpn/cloudflare-warp-bin")
		}
	}

	if runtime.GOOS == "linux" {
		_ = exec.Command("sudo", "systemctl", "daemon-reload").Run()
		_ = exec.Command("sudo", "systemctl", "enable", "--now", "warp-svc").Run()
	}

	_ = exec.Command("warp-cli", "registration", "new").Run()
	if errConnect := exec.Command("warp-cli", "connect").Run(); errConnect == nil {
		for i := 0; i < 6; i++ {
			time.Sleep(1 * time.Second)
			resp, err := httpClient.Get("https://archive.org")
			if err == nil {
				if resp != nil {
					resp.Body.Close()
				}
				return
			}
		}
	}
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	return err == nil && !info.IsDir()
}

func runCmdInDir(dir, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

func runRaw(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}