package backends

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

type PlatformBackend interface {
	GetOSName() string
	Sync()
	Upgrade()
	Search(query string)
	Install(pkgName string)
	Validate(pkgName string) bool
}

func DetectPlatform() PlatformBackend {
	switch runtime.GOOS {
	case "windows":
		return &WindowsBackend{}
	case "darwin":
		return &MacosBackend{}
	case "freebsd", "openbsd", "netbsd":
		return &BsdBackend{OS: runtime.GOOS}
	case "linux":
		return detectLinuxDistro()
	default:
		return &AptBackend{} // Standard default fallback
	}
}

func detectLinuxDistro() PlatformBackend {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return &AptBackend{}
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
		return &PacmanBackend{}
	case strings.Contains(combined, "gentoo"):
		return &GentooEmergeBackend{}
	case strings.Contains(combined, "fedora") || strings.Contains(combined, "rhel"):
		return &DnfBackend{}
	case strings.Contains(combined, "suse"):
		return &ZypperBackend{}
	default:
		return &AptBackend{}
	}
}

func ExecuteSystemCommand(osName, binary string, args []string, forceSudo bool) {
	finalArgs := args
	finalBinary := binary

	if forceSudo && osName != "windows" && osName != "macos" && osName != "nixos" {
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