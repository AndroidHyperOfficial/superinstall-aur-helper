package main

import (
	"fmt"
	"os"
        "io"
	"os/exec"
	"path/filepath"
	"runtime"
        "sync"
	"superinstall/backends"
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

func init() {
	sysConfig = detectPlatform()
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	mode := os.Args[1]

	if mode == "--install-self" {
		handleSelfInstallation()
		return
	}

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

func printUsage() {
	fmt.Println("\033[1;36m=========================================================================\033[0m")
	fmt.Println("\033[1;32m  SUPERinstall! \033[0m - The Universal Multi-Generation Hardened Package Engine")
	fmt.Println("\033[1;36m=========================================================================\033[0m")
	fmt.Println("\nSupported Horizons: OS X Tiger+, Linux 3.0+, Win XP-11, FreeBSD 13+")
	fmt.Println("\nCore Management Enforcements:")
	fmt.Println("  superinstall -Sy                Synchronize local package databases repositories")
	fmt.Println("  superinstall -Syu               Synchronize databases and execute complete system upgrade")
	fmt.Println("  superinstall -search <query>    Query global and local package availability indexes")
	fmt.Println("  superinstall -S <package>       Validate, sandbox-audit, and install package mapping")
	fmt.Println("  superinstall --install-self     Compile and establish tool root entry inside system path")
}

func detectPlatform() TargetConfig {
	switch runtime.GOOS {
	case "windows":
		return TargetConfig{
			OS: "windows", InstallCmd: "winget", SyncCmd: "winget", UpgradeCmd: "winget", SearchCmd: "winget",
			InstallArgs: []string{"install", "--silent"}, SyncArgs: []string{"source", "update"},
			UpgradeArgs: []string{"upgrade", "--all"}, SearchArgs: []string{"search"},
		}
	case "darwin":
		if _, err := exec.LookPath("port"); err == nil {
			return TargetConfig{
				OS: "macos", InstallCmd: "port", SyncCmd: "port", UpgradeCmd: "port", SearchCmd: "port",
				InstallArgs: []string{"install"}, SyncArgs: []string{"selfupdate"},
				UpgradeArgs: []string{"upgrade", "outdated"}, SearchArgs: []string{"search"},
			}
		}
		return TargetConfig{
			OS: "macos", InstallCmd: "brew", SyncCmd: "brew", UpgradeCmd: "brew", SearchCmd: "brew",
			InstallArgs: []string{"install"}, SyncArgs: []string{"update"},
			UpgradeArgs: []string{"upgrade"}, SearchArgs: []string{"search"},
		}
	case "freebsd":
		return TargetConfig{
			OS: "freebsd", InstallCmd: "pkg", SyncCmd: "pkg", UpgradeCmd: "pkg", SearchCmd: "pkg",
			InstallArgs: []string{"install", "-y"}, SyncArgs: []string{"update"},
			UpgradeArgs: []string{"upgrade", "-y"}, SearchArgs: []string{"search"},
		}
	case "linux":
		return detectLinuxDistro()
	default:
		return TargetConfig{OS: "unknown", InstallCmd: "echo"}
	}
}

func detectLinuxDistro() TargetConfig {
	if _, err := exec.LookPath("pacman"); err == nil {
		return TargetConfig{OS: "arch", InstallCmd: "pacman", SyncCmd: "pacman", UpgradeCmd: "pacman", SearchCmd: "pacman"}
	}
	if _, err := exec.LookPath("apt-get"); err == nil {
		return TargetConfig{OS: "debian", InstallCmd: "apt-get", SyncCmd: "apt-get", UpgradeCmd: "apt-get", SearchCmd: "apt-cache"}
	}
	if _, err := exec.LookPath("dnf"); err == nil {
		return TargetConfig{OS: "fedora", InstallCmd: "dnf", SyncCmd: "dnf", UpgradeCmd: "dnf", SearchCmd: "dnf"}
	}
	return TargetConfig{OS: "generic-linux", InstallCmd: "echo"}
}

func handleSelfInstallation() {
	fmt.Println(":: [superinstall] Triggering global system installation matrix...")
	srcFile := getSafeBinaryPath()
	
	var destDir string
	if runtime.GOOS == "windows" {
		destDir = "C:\\Windows\\System32"
	} else {
		destDir = "/usr/local/bin"
	}
	
	destFile := filepath.Join(destDir, "superinstall")
	if runtime.GOOS == "windows" {
		destFile += ".exe"
	}

	// Read input file
	input, err := os.Open(srcFile)
	if err != nil {
		fmt.Printf("Error opening binary source context: %v\n", err)
		return
	}
	defer input.Close()

	// Write output binary metadata safely
	output, err := os.OpenFile(destFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		fmt.Printf("Access verification dropped out. Please re-run command utilizing sudo/administrator privileges.\n")
		return
	}
	defer output.Close()

	_, err = io.Copy(output, input)
	if err == nil {
		fmt.Printf(":: Success! superinstall is now globally established in %s\n", destFile)
	}
}

func handleDatabaseSync() {
	if sysConfig.OS == "arch" {
		p := &backends.PacmanBackend{}
		p.Sync()
		return
	}
	args := append(sysConfig.SyncArgs)
	backends.ExecuteSystemCommand(sysConfig.OS, sysConfig.SyncCmd, args, true)
}

func handleSystemUpgrade() {
	if sysConfig.OS == "arch" {
		p := &backends.PacmanBackend{}
		p.Upgrade()
		return
	}
	args := append(sysConfig.UpgradeArgs)
	backends.ExecuteSystemCommand(sysConfig.OS, sysConfig.UpgradeCmd, args, false)
}

func handlePackageSearch(query string) {
	if sysConfig.OS == "arch" {
		p := &backends.PacmanBackend{}
		p.Search(query)
		return
	}
	args := append(sysConfig.SearchArgs, query)
	backends.ExecuteSystemCommand(sysConfig.OS, sysConfig.SearchCmd, args, true)
}

func handleInstallPipeline(pkg string) {
	if sysConfig.OS == "arch" {
		p := &backends.PacmanBackend{}
		p.Install(pkg)
		return
	}
	args := append(sysConfig.InstallArgs, pkg)
	backends.ExecuteSystemCommand(sysConfig.OS, sysConfig.InstallCmd, args, false)
}

func getSafeBinaryPath() string {
	exePath, err := os.Executable()
	if err != nil || exePath == "" {
		return os.Args[0]
	}
	return exePath
}

// IO helper proxy function for cross-architecture copies
var ioCopyBufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 32*1024)
		return &b
	},
}

func ioCopyBytes(dst io.Writer, src io.Reader) (written int64, err error) {
	bufp := ioCopyBufferPool.Get().(*[]byte)
	defer ioCopyBufferPool.Put(bufp)
	return io.CopyBuffer(dst, src, *bufp)
}