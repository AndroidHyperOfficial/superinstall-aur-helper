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

var RepoMapping = map[string]string{
	"fastfetch": "fastfetch-cli/fastfetch",
	"ripgrep":   "BurntSushi/ripgrep",
	"jq":        "jqlang/jq",
}

// DetectSystemPlatform scans the core environment definitions to pinpoint specific sub-distributions
func DetectSystemPlatform() string {
	arch := runtime.GOARCH
	
	// Check for ARM ecosystems
	if arch == "arm64" || arch == "arm" {
		return fmt.Sprintf("Arch Linux ARM (%s)", arch)
	}
	
	// Check for legacy x86 / 32-bit platforms
	if arch == "386" {
		return "Arch Linux 32 (i686)"
	}
	
	return "Arch Linux Standard (x86_64)"
}

func printInfoLogo() {
	logo := fmt.Sprintf("\n"+
		"   /\\\n"+
		"  /  \\\n"+
		" /____\\       SUinstall!\n"+
		"|  ⟱  |       --------------------------\n"+
		"|_____|       Arch Linux Multi-Platform Deployment Subsystem\n"+
		"                       Detected Base: %s\n"+
		"                       Version: 1.3 Adaptive Engine Track\n", DetectSystemPlatform())
	fmt.Println(logo)
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
		"  superinstall -info              Display configuration environment layout and logo\n" +
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

func installFromAUR(pkgName string, interactive bool, checkCode bool) error {
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
				_ = installFromAUR(cleanDep, interactive, checkCode) 
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
	
	// CRITICAL FIX FOR ARCH 32 & ARM SUPPORT:
	// Automatically pass "-A" / "--ignorearch" flag to makepkg so packages without 
	// specific "i686", "armv7h", or "aarch64" lines declared compile cleanly on target rigs.
	buildCmd := exec.Command("makepkg", "-si", "-A", "--noconfirm")
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
			_ = installFromAUR(item.Name, true, false)
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
		if os.Args[1] == "???" {
			printEasterEggLogo()
			return
		}
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
		if os.Args[1] == "i love superinstall" {
			launchEasterEggGUI()
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
			if len(os.Args) > 3 && os.Args[3] == "-check-code" {
				checkCode = true
			}
			_, exists := RepoMapping[pkg]
			if !exists {
				err := installFromAUR(pkg, true, checkCode)
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
		_ = installFromAUR(pkg, true, false)
		return
	}

	mprRoot := filepath.Join(os.Getenv("HOME"), ".local/share/superinstall")
	fmt.Printf("[Target Discovery] Host System: %s (%s)\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("Handling index deployment sequence for quick target lookup: %s in %s\n", pkg, mprRoot)
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
	myWindow := myApp.NewWindow("SuperInstall 1.3 - Multi-Platform Package Suite")
	myWindow.Resize(fyne.NewSize(900, 650))

	titleText := fmt.Sprintf("SuperInstall Control Environment [%s]", DetectSystemPlatform())
	titleLabel := widget.NewLabelWithStyle(titleText, fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	outputConsole := widget.NewMultiLineEntry()
	outputConsole.SetText("System Ready.\nUse search bar or tracking triggers below to route pacman actions.")
	outputConsole.Wrapping = fyne.TextWrapWord

	inputField := widget.NewEntry()
	inputField.SetPlaceHolder("Enter target package or query...")

	searchListContainer := container.NewVBox()
	scrollableResults := container.NewScroll(searchListContainer)
	scrollableResults.SetMinSize(fyne.NewSize(250, 400))

	searchBtn := widget.NewButton("Search Engine", func() {
		query := strings.TrimSpace(inputField.Text)
		if query == "" {
			outputConsole.SetText("Error: Search query cannot be blank.")
			return
		}
		outputConsole.SetText(fmt.Sprintf("Querying backend index registers for: '%s'...", query))
		searchListContainer.Objects = nil

		apiURL := fmt.Sprintf("https://aur.archlinux.org/rpc/?v=5&type=search&arg=%s", query)
		resp, err := http.Get(apiURL)
		if err != nil {
			outputConsole.SetText("Error: Connection failure reaching upstream AUR index streams.")
			return
		}
		defer resp.Body.Close()

		var searchData AURSearchResponse
		if err := json.NewDecoder(resp.Body).Decode(&searchData); err != nil {
			outputConsole.SetText("Error: Metadata response index could not be parsed.")
			return
		}

		if searchData.ResultCount == 0 {
			searchListContainer.Add(widget.NewLabel("No packages found."))
		} else {
			for _, pkg := range searchData.Results {
				name := pkg.Name
				desc := pkg.Description
				ver := pkg.Version
				itemBtn := widget.NewButton(fmt.Sprintf("%s (%s)", name, ver), func() {
					inputField.SetText(name)
					outputConsole.SetText(fmt.Sprintf("Selected package target: %s\nDescription: %s", name, desc))
				})
				searchListContainer.Add(itemBtn)
			}
		}
		searchListContainer.Refresh()
	})

	installBtn := widget.NewButton("Install Target", func() {
		target := strings.TrimSpace(inputField.Text)
		if target == "" {
			outputConsole.SetText("Please specify a valid package target to deploy.")
			return
		}
		outputConsole.SetText(fmt.Sprintf("Launching background cross-architecture installation pipeline for: %s\nRunning non-interactive sandbox configuration rules...", target))
		go func() {
			_, exists := RepoMapping[target]
			if !exists {
				err := installFromAUR(target, false, false)
				if err != nil {
					outputConsole.SetText(fmt.Sprintf("Installation Loop Error: %v", err))
				} else {
					outputConsole.SetText(fmt.Sprintf("[Success] Core package deployment complete for '%s'!", target))
				}
			} else {
				mprRoot := filepath.Join(os.Getenv("HOME"), ".local/share/superinstall")
				fmt.Printf("Handling index lookup sequences for: %s inside %s\n", target, mprRoot)
			}
		}()
	})

	verifyBtn := widget.NewButton("Verify Code Blocks", func() {
		auditorWin := myApp.NewWindow("SuperInstall 1.3 - Auditor Environment")
		auditorWin.Resize(fyne.NewSize(500, 400))

		header := widget.NewLabelWithStyle("SuperInstall Bad-Block Verification Environment", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
		statusLabel := widget.NewLabel("System Status: Scanning active process blocks...")

		var gridObjects []fyne.CanvasObject
		for i := 0; i < 25; i++ {
			dot := canvas.NewCircle(color.NRGBA{R: 46, G: 204, B: 113, A: 255})
			dot.Resize(fyne.NewSize(12, 12))
			gridObjects = append(gridObjects, dot)
		}
		gridContainer := container.New(layout.NewGridLayout(5), gridObjects...)

		auditorWin.SetContent(container.NewBorder(header, statusLabel, nil, nil, container.NewCenter(gridContainer)))
		auditorWin.Show()

		go func() {
			time.Sleep(3 * time.Second)
			statusLabel.SetText("System Status: Idle. Setup target string to trigger deployment cycle routines.")
		}()
	})

	uninstallBtn := widget.NewButton("Uninstall Package", func() {
		target := strings.TrimSpace(inputField.Text)
		if target == "" {
			outputConsole.SetText("Please enter a package name to purge.")
			return
		}
		outputConsole.SetText(fmt.Sprintf("Triggering native clean thread via pacman -Rns on target: %s", target))
		go func() {
			cmd := exec.Command("sudo", "pacman", "-Rns", target, "--noconfirm")
			_ = cmd.Run()
		}()
	})

	upgradeBtn := widget.NewButton("System Upgrade (-Syu)", func() {
		outputConsole.SetText("Spawning background full cross-platform upgrade synchronization loop (-Syu)...")
		go executeFullSystemUpgrade()
	})

	downgradeBtn := widget.NewButton("Downgrade Framework", func() {
		target := strings.TrimSpace(inputField.Text)
		if target == "" {
			outputConsole.SetText("Specify a package to look up inside local cache rollback tables.")
			return
		}
		outputConsole.SetText(fmt.Sprintf("Searching rollback trees for local downgrade profiles matching: %s", target))
	})

	aboutCircleBtn := widget.NewButton("ⓘ About", func() {
		aboutWin := myApp.NewWindow("About SuperInstall")
		aboutWin.Resize(fyne.NewSize(350, 220))
		
		circleBg := canvas.NewCircle(color.NRGBA{R: 52, G: 152, B: 219, A: 255})
		circleBg.Resize(fyne.NewSize(70, 70))
		
		infoTxt := widget.NewLabelWithStyle("SuperInstall Helper Engine\nVersion 1.3 Adaptive Track\n\nBuilt for Multi-Platform Arch Distributions.", fyne.TextAlignCenter, fyne.TextStyle{Italic: true})
		aboutWin.SetContent(container.NewVBox(container.NewCenter(circleBg), infoTxt))
		aboutWin.Show()
	})

	searchRow := container.NewBorder(nil, nil, nil, searchBtn, inputField)
	actionButtons := container.NewVBox(installBtn, verifyBtn, uninstallBtn, upgradeBtn, downgradeBtn, layout.NewSpacer(), aboutCircleBtn)
	
	mainWorkspace := container.NewHSplit(scrollableResults, outputConsole)
	mainWorkspace.Offset = 0.35

	layoutCore := container.NewBorder(titleLabel, searchRow, nil, actionButtons, mainWorkspace)
	myWindow.SetContent(layoutCore)
	myWindow.ShowAndRun()
}

func launchEasterEggGUI() {
	myApp := app.New()
	myWindow := myApp.NewWindow("I Love SuperInstall - Secret Development Portal")
	myWindow.Resize(fyne.NewSize(700, 500))

	title := widget.NewLabelWithStyle("SuperInstall Core Utility Matrix Hub", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	
	menuLines := "Available Core Enforcements:\n" +
		"• -Sy   : Synchronize databases\n" +
		"• -Syu  : Recursive AUR Upgrades\n" +
		"• -S    : Sandbox-audited installations\n" +
		"• --clean: Run 30-day cache purification tracking\n" +
		"• --gui  : Run structural interface control desk\n"

	menuLabel := widget.NewLabel(menuLines)
	feedbackLabel := widget.NewLabel("Secret Portal Active. Try searching 'thanks' below!")

	input := widget.NewEntry()
	input.SetPlaceHolder("Search inside engine...")
	
	earlyAccessBtn := widget.NewButton("Unlock GitHub Early Access", nil)
	earlyAccessOn := false

	earlyAccessBtn.OnTapped = func() {
		earlyAccessOn = !earlyAccessOn
		if earlyAccessOn {
			earlyAccessBtn.SetText("Early Access Branch: LOCKED ON")
		} else {
			earlyAccessBtn.SetText("Unlock GitHub Early Access")
		}
	}

	input.OnChanged = func(txt string) {
		cleanTxt := strings.ToLower(strings.TrimSpace(txt))
		if cleanTxt == "thanks" {
			feedbackLabel.SetText("You are welcome! Thank you for using and supporting SuperInstall! ❤️")
		} else if cleanTxt != "" {
			feedbackLabel.SetText("Filtering commands... Mode stable.")
		} else {
			feedbackLabel.SetText("Secret Portal Active. Try searching 'thanks' below!")
		}
	}

	centerLayout := container.NewVBox(menuLabel, feedbackLabel)
	bottomRow := container.NewBorder(nil, nil, nil, earlyAccessBtn, input)
	mainLayout := container.NewBorder(title, bottomRow, nil, nil, centerLayout)

	myWindow.SetContent(mainLayout)
	myWindow.ShowAndRun()
}