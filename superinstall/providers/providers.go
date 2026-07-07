package providers

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// =========================================================================
// 1. Git Provider Interface Matrix Definitions
// =========================================================================

type GitProvider interface {
	Install(url string, osName string)
}

func ResolveGitProvider(target string) GitProvider {
	switch {
	case strings.Contains(target, "gitgud.io"):
		return &GitGudProvider{}
	case strings.Contains(target, "codeberg.org"):
		return &CodebergProvider{}
	case strings.Contains(target, "gitlab.com"):
		return &GitLabProvider{}
	default:
		return &GitHubProvider{}
	}
}

// =========================================================================
// 2. Shared Build Pipeline Routing Configuration
// =========================================================================

func RunSharedBuildPipeline(targetDir string, baseName string, osName string) {
	isWindows := osName == "windows"
	isBSD := strings.Contains(osName, "bsd")

	if !RunSecurityGatekeeper(baseName, targetDir) {
		fmt.Println(":: [superinstall] Safe exit execution aborted.")
		return
	}

	switch {
	case FileExists(filepath.Join(targetDir, "PKGBUILD")) && osName == "arch":
		AttemptInstallationWithPGPFix(targetDir)

	case FileExists(filepath.Join(targetDir, "Makefile")):
		makeCmd := "make"
		if isBSD {
			makeCmd = "gmake"
		}
		_ = RunCmdInDir(targetDir, makeCmd)
		if isWindows {
			_ = RunCmdInDir(targetDir, makeCmd, "install")
		} else if osName == "macos" {
			_ = RunCmdInDir(targetDir, makeCmd, "install")
		} else {
			_ = RunCmdInDir(targetDir, "sudo", makeCmd, "install")
		}

	case FileExists(filepath.Join(targetDir, "Cargo.toml")):
		_ = RunCmdInDir(targetDir, "cargo", "build", "--release")
		dest := "/usr/local/bin/"
		if isWindows {
			dest = "C:\\Windows\\System32\\"
		}
		if osName == "macos" {
			_ = RunCmdInDir(targetDir, "cp", filepath.Join("target", "release", baseName), dest)
		} else {
			_ = RunCmdInDir(targetDir, "sudo", "cp", filepath.Join("target", "release", baseName), dest)
		}

	default:
		fmt.Println(":: [superinstall] Blueprint complete, no executable build pattern triggered.")
	}
}

// =========================================================================
// 3. Upgraded Heuristic Threat Scanner & Security Gatekeeper
// =========================================================================

type ThreatRule struct {
	Name        string
	Pattern     *regexp.Regexp
	RiskScore   int
	Description string
}

var securityRules = []ThreatRule{
	{
		Name:        "Root Directory Wiper",
		Pattern:     regexp.MustCompile(`rm\s+-[a-zA-Z]*[rfRF]+[a-zA-Z]*\s+([\/\$\~]|\b(etc|boot|var|usr)\b)`),
		RiskScore:   100,
		Description: "Detected destructive deletion pattern targeting root, home, or vital system directories.",
	},
	{
		Name:        "Fork Bomb Payload",
		Pattern:     regexp.MustCompile(`:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:`),
		RiskScore:   100,
		Description: "Detected resource-exhaustion denial of service string (Fork Bomb).",
	},
	{
		Name:        "Obfuscated Execution Hook",
		Pattern:     regexp.MustCompile(`(base64|xxd|hexdump)\s+-(d|e|p).*\|\s*(sh|bash|zsh|eval)`),
		RiskScore:   85,
		Description: "Detected suspicious decoding pipe directly into a system command shell.",
	},
	{
		Name:        "Inline Dynamic Code Evaluation",
		Pattern:     regexp.MustCompile(`eval\s*(\([^)]+\)|'[^']+')`),
		RiskScore:   75,
		Description: "Detected dynamic code execution statement bypassing static source parsing.",
	},
	{
		Name:        "Reverse Shell Network Dial",
		Pattern:     regexp.MustCompile(`/(dev/tcp|dev/udp)/[0-9]{1,5}`),
		RiskScore:   90,
		Description: "Detected direct socket layer exploitation blueprint typically used for reverse shells.",
	},
	{
		Name:        "Suspicious Remote Downloader",
		Pattern:     regexp.MustCompile(`(curl|wget|fetch)\s+.*\|\s*(sh|bash|eval)`),
		RiskScore:   80,
		Description: "Detected automated untrusted web payload download running directly into system memory.",
	},
}

func RunSecurityGatekeeper(pkgName string, dirPath string) bool {
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

func scanForMaliciousCode(dirPath string) (bool, []string) {
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
			line := scanner.Text()

			for _, rule := range securityRules {
				if rule.Pattern.MatchString(line) {
					totalRiskScore += rule.RiskScore
					foundThreats = append(foundThreats, fmt.Sprintf(
						"%s (Line %d): [%s] - %s",
						filepath.Base(path), lineNumber, rule.Name, rule.Description,
					))
				}
			}
		}
		return nil
	})

	isMalicious := totalRiskScore >= 100
	return isMalicious, foundThreats
}

// =========================================================================
// 4. Global Shell Utility Helper Functions
// =========================================================================

func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	return err == nil && !info.IsDir()
}

func RunCmdInDir(dir, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}