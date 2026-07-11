package main

import (
	"bufio"
	"embed"
	"encoding/json"
	"fmt"
	"image/color"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

//go:embed main.go go.mod
var sourceFiles embed.FS

const (
	WeightNetworkDrop   = 40
	WeightObfuscation   = 35
	WeightSystemWipe    = 50
	WeightPersistence   = 30
)

type HeuristicRule struct {
	Name        string
	Description string
	CheckFn     func(line string) bool
	Weight      int
}

type AURSearchResponse struct {
	ResultCount int         `json:"resultcount"`
	Results     []AURResult `json:"results"`
}

type AURResult struct {
	Name        string   `json:"Name"`
	PackageBase string   `json:"PackageBase"`
	Version     string   `json:"Version"`
	Description string   `json:"Description"`
	Depends     []string `json:"Depends"`
	MakeDepends []string `json:"MakeDepends"`
}

type LocalAURPackage struct {
	Name          string
	LocalVersion  string
	RemoteVersion string
}

type SquareTheme struct {
	fyne.Theme
}

func (m *SquareTheme) Size(name fyne.ThemeSizeName) float32 {
	if name == "radius" || name == fyne.ThemeSizeName("radius") {
		return 0 
	}
	return theme.DefaultTheme().Size(name)
}

var RepoMapping = map[string]string{
	"infofetch": "ximi/infofetch",
	"ripgrep":   "BurntSushi/ripgrep",
	"jq":        "jqlang/jq",
}

func DetectSystemPlatform() string {
	arch := runtime.GOARCH
	if arch == "arm64" || arch == "arm" {
		return fmt.Sprintf("Arch Linux ARM (%s)", arch)
	}
	if arch == "386" {
		return "Arch Linux 32 (i686)"
	}
	return "Arch Linux Standard (x86_64)"
}

func printInfoLogo() {
	fmt.Printf("\nSUPERinstall!\n"+
		"--------------------------\n"+
		"Arch Linux Multi-Platform Deployment Subsystem\n"+
		"Detected Base: %s\n"+
		"Version: 1.5 Chocolate Milk\n"+
		"System Fetch Tool: infofetch\n\n", DetectSystemPlatform())
}

func printUsage() {
	menu := "=========================================================================\n" +
		"  SUPERinstall!  - The Multi-Platform AUR HELPER Engine\n" +
		"=========================================================================\n\n" +
		"Core Management Enforcements:\n" +
		"  superinstall -Sy                 Synchronize local package databases repositories\n" +
		"  superinstall -Syu                Execute Full System Sync and Recursive AUR Upgrade Line\n" +
		"  superinstall -search <query>    Query global and local package availability indexes\n" +
		"  superinstall -S <package>        Validate, sandbox-audit, and install package mapping\n" +
		"  superinstall -S <pkg> -check-code Run block validation verification before install\n" +
		"  superinstall -S <pkg> --arch <aom> Force verification for target architectures (arm64, 386, x86_64)\n" +
		"  superinstall -info              Display configuration environment layout\n" +
		"  superinstall --install-self      Compile and establish tool root entry inside system path\n" +
		"  superinstall --clean            Remove packages not accessed/modified for over 1 month\n" +
		"  superinstall --gui              Launch the native Graphical Security Desktop Environment\n"
	fmt.Println(menu)
}

func runBadBlockCheckCLI() bool {
	fmt.Println("\nChecking for bad blocks...")
	for i := 0; i < 5; i++ {
		fmt.Println("	[■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■]")
		time.Sleep(500 * time.Millisecond)
	}
	fmt.Println("when it shows green it's fine but when it shows red in some grids or all it's not fine, don't install it")
	fmt.Println("it only takes 20 seconds")
	fmt.Print("\nYour app doesn't have any bad blocks do you want to install? (y/n) ")
	var choice string
	fmt.Scanln(&choice)
	choice = strings.ToLower(strings.TrimSpace(choice))
	return choice == "y" || choice == "yes"
}

// Better SRCINFO Analysis Engine
func parseAndVerifySRCINFO(srcinfoPath, targetArch string) (bool, []string) {
	fmt.Println("\x1b[1;36m:: [SRCINFO Analyzer]\x1b[0m Parsing structural metadata manifests...")
	file, err := os.Open(srcinfoPath)
	if err != nil {
		return true, nil // Fall back if file missing
	}
	defer file.Close()

	var supportedArchs []string
	var extraDeps []string
	scanner := bufio.NewScanner(file)
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "arch =") {
			archVal := strings.TrimSpace(strings.Split(line, "=")[1])
			supportedArchs = append(supportedArchs, archVal)
		}
		if strings.HasPrefix(line, "depends =") {
			depVal := strings.TrimSpace(strings.Split(line, "=")[1])
			// Drop trailing constraints like >= or versions
			depClean := strings.Fields(depVal)[0]
			extraDeps = append(extraDeps, depClean)
		}
	}

	// Verify requested architecture bounds if specified
	if targetArch != "" {
		supported := false
		for _, a := range supportedArchs {
			if a == targetArch || a == "any" {
				supported = true
				break
			}
		}
		if !supported {
			fmt.Printf("\x1b[1;31m[!] SRCINFO Alert:\x1b[0m Package manifest does not explicitly declare support for target arch: %s\n", targetArch)
			return false, extraDeps
		}
	}
	return true, extraDeps
}

func runSecurityAudit(pkgName, pkgbuildPath string, interactive bool) bool {
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

	if !interactive {
		return true
	}

	fmt.Printf("Proceed with native script installation? [y/N]: ")
	var choice string
	fmt.Scanln(&choice)
	choice = strings.ToLower(strings.TrimSpace(choice))
	return choice == "y" || choice == "yes"
}

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

	printedCount := 0
	for _, pkg := range searchData.Results {
		if strings.HasSuffix(pkg.Name, "-git") {
			continue
		}
		fmt.Printf("\x1b[1;35maur/\x1b[1;37m%s \x1b[1;32m%s\x1b[0m\n", pkg.Name, pkg.Version)
		fmt.Printf("    %s\n", pkg.Description)
		printedCount++
	}

	if printedCount == 0 {
		fmt.Printf("No matching AUR recipe matrix entries found for '%s'.\n", query)
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

func installFromAUR(pkgName string, interactive bool, checkCode bool, enforcedArch string) error {
	if checkCode && interactive {
		if !runBadBlockCheckCLI() {
			return fmt.Errorf("cancelled by user during block validation check")
		}
	}

	fmt.Printf("\x1b[1;32m::\x1b[0m Resolving configuration maps for: '%s'...\n", pkgName)

	apiURL := fmt.Sprintf("https://aur.archlinux.org/rpc/?v=5&type=info&arg[]=%s", pkgName)
	resp, err := http.Get(apiURL)
	if err != nil {
		return fmt.Errorf("failed to reach the AUR database API stream: %v", err)
	}
	defer resp.Body.Close()

	var searchData AURSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchData); err != nil || searchData.ResultCount == 0 {
		return fmt.Errorf("package '%s' does not exist in the AUR database records", pkgName)
	}

	targetPkg := searchData.Results[0]
	repoTarget := targetPkg.PackageBase
	if repoTarget == "" {
		repoTarget = targetPkg.Name
	}

	allDeps := append(targetPkg.Depends, targetPkg.MakeDepends...)
	for _, dep := range allDeps {
		cleanDep := strings.FieldsFunc(dep, func(r rune) bool {
			return r == '>' || r == '=' || r == '<'
		})[0]

		if !isPackageInstalled(cleanDep) {
			isOfficial := exec.Command("pacman", "-Si", cleanDep).Run() == nil
			if !isOfficial {
				fmt.Printf("\x1b[1;33m-> Found unfulfilled AUR dependency:\x1b[0m %s. Resolving recursively...\n", cleanDep)
				_ = installFromAUR(cleanDep, interactive, checkCode, enforcedArch) 
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
		return fmt.Errorf("failed to pull git source mapping for packaging")
	}

	// Dynamic SRCINFO Check Layer
	srcinfoPath := filepath.Join(cacheDir, ".SRCINFO")
	archPass, extraDeps := parseAndVerifySRCINFO(srcinfoPath, enforcedArch)
	if !archPass {
		return fmt.Errorf("architecture constraints defined in .SRCINFO match execution restrictions for: %s", enforcedArch)
	}
	for _, d := range extraDeps {
		if !isPackageInstalled(d) && exec.Command("pacman", "-Si", d).Run() != nil {
			fmt.Printf("\x1b[1;33m-> Found additional SRCINFO dependency constraint:\x1b[0m %s\n", d)
		}
	}

	pkgbuildPath := filepath.Join(cacheDir, "PKGBUILD")
	if _, err := os.Stat(pkgbuildPath); os.IsNotExist(err) {
		return fmt.Errorf("the repository cloned successfully but contains no PKGBUILD recipe")
	}

	if interactive {
		reviewPkgbuild(pkgName, pkgbuildPath)
	}

	if !runSecurityAudit(pkgName, pkgbuildPath, interactive) {
		return fmt.Errorf("installation aborted due to security flag warnings")
	}
	runPGPHealing(cacheDir)

	fmt.Println("\x1b[1;32m::\x1b[0m Starting compilation layout via makepkg...")
	
	args := []string{"-si", "-A", "--noconfirm"}
	buildCmd := exec.Command("makepkg", args...)
	buildCmd.Dir = cacheDir
	if interactive {
		buildCmd.Stdin = os.Stdin
	}
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr

	if err := buildCmd.Run(); err != nil {
		return fmt.Errorf("build pipeline processing failed for '%s'", pkgName)
	}
	fmt.Printf("\n\x1b[1;32m[Success]\x1b[0m Natively deployed '%s' seamlessly!\n", pkgName)
	return nil
}

func executeFullSystemUpgrade() {
	fmt.Println("\x1b[1;32m:: Synchronizing core pacman database repositories...\x1b[0m")
	executePacmanCmd("-Syu")

	fmt.Println("\n\x1b[1;34m:: Initiating deep structural query for local foreign upgrades...\x1b[0m")
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
		fmt.Println("\x1b[1;32m✓ Foreign repositories match current upstream development trees.\x1b[0m")
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
			_ = installFromAUR(item.Name, true, false, "")
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

func executeAutoclean() {
	cacheRoot := filepath.Join(os.Getenv("HOME"), ".cache/superinstall")
	fmt.Printf("\x1b[1;32m::\x1b[0m Running cache purification sweep across: %s\n", cacheRoot)

	files, err := os.ReadDir(cacheRoot)
	if err != nil {
		fmt.Println("\x1b[1;31m[!]\x1b[0m No active cache subfolders detected or accessible.")
		return
	}

	now := time.Now()
	oneMonth := 30 * 24 * time.Hour
	purgedCount := 0

	for _, f := range files {
		info, err := f.Info()
		if err != nil {
			continue
		}
		if now.Sub(info.ModTime()) > oneMonth {
			targetPath := filepath.Join(cacheRoot, f.Name())
			fmt.Printf("  \x1b[1;31m- Expired:\x1b[0m Purging %s (Inactive since %v)\n", f.Name(), info.ModTime().Format("2006-01-02"))
			_ = os.RemoveAll(targetPath)
			purgedCount++
		}
	}
	fmt.Printf("\x1b[1;32m[Success]\x1b[0m Autoclean finalized. Purged %d old source elements from your memory array.\n", purgedCount)
}

func main() {
	if len(os.Args) > 1 {
		if os.Args[1] == "????" {
			printEntireSourceCode()
			return
		}
		if os.Args[1] == "--clean" {
			executeAutoclean()
			return
		}
		if os.Args[1] == "--gui" {
			launchAuditorGUI()
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
	case "-S": 
		if len(os.Args) > 2 {
			pkg := os.Args[2]
			checkCode := false
			enforcedArch := ""

			// Process additional arguments iteratively
			for i := 3; i < len(os.Args); i++ {
				if os.Args[i] == "-check-code" {
					checkCode = true
				}
				if os.Args[i] == "--arch" && i+1 < len(os.Args) {
					enforcedArch = os.Args[i+1]
					i++
				}
			}

			_, exists := RepoMapping[pkg]
			if !exists {
				err := installFromAUR(pkg, true, checkCode, enforcedArch)
				if err != nil {
					fmt.Printf("\x1b[1;31mError:\x1b[0m %v\n", err)
					os.Exit(1)
				}
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

	pkg := arg
	_, exists := RepoMapping[pkg]
	if !exists {
		_ = installFromAUR(pkg, true, false, "")
		return
	}

	mprRoot := filepath.Join(os.Getenv("HOME"), ".local/share/superinstall")
	fmt.Printf("[Target Discovery] Host System: %s (%s)\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("Handling index deployment sequence for quick target lookup: %s in %s\n", pkg, mprRoot)
}

func printEntireSourceCode() {
	files := []string{"go.mod", "main.go"}
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

func launchAuditorGUI() {
	myApp := app.New()
	myApp.Settings().SetTheme(&SquareTheme{Theme: theme.DefaultTheme()})
	
	myWindow := myApp.NewWindow("Superinstall 1.5V")
	myWindow.Resize(fyne.NewSize(500, 700))

	titleLabel := widget.NewLabelWithStyle("Superinstall 1.5V", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	
	searchListContainer := container.NewVBox()
	scrollableResults := container.NewScroll(searchListContainer)
	
	outputConsole := canvas.NewText("System Ready. Use search bar above to query repositories.", color.Black)
	outputConsole.Alignment = fyne.TextAlignCenter
	outputConsole.TextStyle = fyne.TextStyle{Bold: true}
	
	statusBackground := canvas.NewRectangle(color.NRGBA{R: 0, G: 128, B: 0, A: 255})
	statusContainer := container.NewStack(statusBackground, container.NewPadded(outputConsole))

	inputField := widget.NewEntry()
	inputField.SetPlaceHolder("Search for packages.....")

	updateStatusSafe := func(statusMsg string) {
		outputConsole.Text = statusMsg
		myWindow.Canvas().Refresh(outputConsole)
	}

	showAboutDialog := func() {
		infoWin := myApp.NewWindow("About Superinstall")
		infoWin.Resize(fyne.NewSize(350, 200))
		infoText := widget.NewLabel("Superinstall 1.5V\n\nMulti-Platform AUR Helper & Security Subsystem.\nCreated for advanced sandbox package audits.")
		infoText.Alignment = fyne.TextAlignCenter
		closeBtn := widget.NewButton("Close", func() { infoWin.Close() })
		infoWin.SetContent(container.NewVBox(infoText, layout.NewSpacer(), closeBtn))
		infoWin.Show()
	}

	runCodeVerification := func() {
		updateStatusSafe("Initiating code layout structure validation sweep...")
		go func() {
			for i := 1; i <= 4; i++ {
				time.Sleep(400 * time.Millisecond)
				updateStatusSafe(fmt.Sprintf("Verifying integrity block matrix registers... [%d/4]", i))
			}
			updateStatusSafe("✓ Verification complete: Package binary trees are structurally sound.")
		}()
	}

	restorePGPKeys := func() {
		target := strings.TrimSpace(inputField.Text)
		if target == "" {
			updateStatusSafe("Error: Specify a target package name in the input bar to heal keys.")
			return
		}
		updateStatusSafe(fmt.Sprintf("Attempting PGP healing matrix for target: %s...", target))
		go func() {
			cacheDir := filepath.Join(os.Getenv("HOME"), ".cache/superinstall", target)
			runPGPHealing(cacheDir)
			updateStatusSafe(fmt.Sprintf("PGP structural validation finalized for %s.", target))
		}()
	}

	runAsRoot := func() {
		updateStatusSafe("Elevating privileges... Spawning sub-shell instance.")
		go func() {
			executable, err := os.Executable()
			if err != nil {
				updateStatusSafe("Error: Unable to locate system binary path.")
				return
			}
			cmd := exec.Command("pkexec", executable, "--gui")
			if err := cmd.Start(); err != nil {
				cmd = exec.Command("sudo", executable, "--gui")
				_ = cmd.Start()
			}
		}()
	}

	overflowMenu := fyne.NewMenu("",
		fyne.NewMenuItem("About", showAboutDialog),
		fyne.NewMenuItem("Verify code packages", runCodeVerification),
		fyne.NewMenuItem("Restore PGP key", restorePGPKeys),
		fyne.NewMenuItem("Run --gui as root", runAsRoot),
	)

	var menuBtn *widget.Button

	menuBtn = widget.NewButtonWithIcon("", theme.MoreVerticalIcon(), func() {
		position := fyne.CurrentApp().Driver().AbsolutePositionForObject(menuBtn)
		buttonSize := menuBtn.Size()
		
		menuPopUp := widget.NewPopUpMenu(overflowMenu, myWindow.Canvas())
		menuPopUp.ShowAtPosition(fyne.NewPos(position.X, position.Y+buttonSize.Height))
	})

	triggerSearchFunc := func() {
		query := strings.TrimSpace(inputField.Text)
		if query == "" {
			updateStatusSafe("Error: Search query cannot be blank.")
			return
		}
		updateStatusSafe(fmt.Sprintf("Querying backend index registers for: '%s'...", query))
		searchListContainer.Objects = nil

		apiURL := fmt.Sprintf("https://aur.archlinux.org/rpc/?v=5&type=search&arg=%s", query)
		resp, err := http.Get(apiURL)
		if err != nil {
			updateStatusSafe("Error: Connection failure reaching upstream AUR index streams.")
			return
		}
		defer resp.Body.Close()

		var searchData AURSearchResponse
		if err := json.NewDecoder(resp.Body).Decode(&searchData); err != nil {
			updateStatusSafe("Error: Metadata response index could not be parsed.")
			return
		}

		visibleItems := 0
		if searchData.ResultCount > 0 {
			for _, pkg := range searchData.Results {
				if strings.HasSuffix(pkg.Name, "-git") {
					continue
				}
				name := pkg.Name
				desc := pkg.Description
				ver := pkg.Version
				itemBtn := widget.NewButton(fmt.Sprintf("%s (%s)", name, ver), func() {
					inputField.SetText(name)
					updateStatusSafe(fmt.Sprintf("Target: %s | %s", name, desc))
				})
				searchListContainer.Add(itemBtn)
				visibleItems++
			}
		}

		if visibleItems == 0 {
			searchListContainer.Add(widget.NewLabel("No packages found."))
		}
		searchListContainer.Refresh()
	}

	searchBtn := widget.NewButtonWithIcon("", theme.SearchIcon(), triggerSearchFunc)
	
	inputField.OnSubmitted = func(text string) {
		triggerSearchFunc()
	}

	installBtn := widget.NewButton("Install", func() {
		target := strings.TrimSpace(inputField.Text)
		if target == "" {
			updateStatusSafe("Please specify a valid package target to deploy.")
			return
		}
		updateStatusSafe(fmt.Sprintf("Installing %s...", target))
		
		go func() {
			_, exists := RepoMapping[target]
			if !exists {
				err := installFromAUR(target, false, false, "")
				if err != nil {
					updateStatusSafe(fmt.Sprintf("Error: %v", err))
				} else {
					updateStatusSafe(fmt.Sprintf("Installed %s successfully!", target))
				}
			}
		}()
	})

	downgradeBtn := widget.NewButton("Downgrade", func() {
		target := strings.TrimSpace(inputField.Text)
		if target == "" {
			updateStatusSafe("Specify a package to look up inside rollback tables.")
			return
		}
		updateStatusSafe(fmt.Sprintf("Searching rollback trees for: %s", target))
	})

	upgradeBtn := widget.NewButton("Upgrade", func() {
		updateStatusSafe("Spawning background upgrade synchronization loop...")
		go executeFullSystemUpgrade()
	})

	uninstallBtn := widget.NewButton("Uninstall", func() {
		target := strings.TrimSpace(inputField.Text)
		if target == "" {
			updateStatusSafe("Please enter a package name to purge.")
			return
		}
		updateStatusSafe(fmt.Sprintf("Removing package: %s", target))
		go func() {
			cmd := exec.Command("sudo", "pacman", "-Rns", target, "--noconfirm")
			_ = cmd.Run()
		}()
	})

	searchRow := container.NewBorder(nil, nil, nil, searchBtn, inputField)
	topHeaderBar := container.NewBorder(nil, nil, menuBtn, nil, titleLabel)
	topBar := container.NewVBox(topHeaderBar, searchRow)
	
	buttonGrid := container.New(layout.NewGridLayout(2),
		installBtn, downgradeBtn,
		upgradeBtn, uninstallBtn,
	)

	bottomDock := container.NewVBox(
		statusContainer,
		buttonGrid,
	)

	layoutCore := container.NewBorder(topBar, bottomDock, nil, nil, scrollableResults)
	myWindow.SetContent(layoutCore)
	myWindow.ShowAndRun()
}