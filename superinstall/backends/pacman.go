package backends

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"superinstall/providers"
	"time"
)

type PacmanBackend struct{}

var pacmanHttpClient = &http.Client{Timeout: 6 * time.Second}

func (p *PacmanBackend) GetOSName() string {
	return "arch"
}

func (p *PacmanBackend) Sync() {
	fmt.Println(":: [superinstall] Executing repository database synchronization mapping for: arch")
	ExecuteSystemCommand("arch", "pacman", []string{"-Sy"}, true)
}

func (p *PacmanBackend) Upgrade() {
	fmt.Println(":: [superinstall] Initiating global system transaction rollback and upgrades for: arch")
	ExecuteSystemCommand("arch", "sudo", []string{"pacman", "-Syu", "--noconfirm"}, false)
}

func (p *PacmanBackend) Search(query string) {
	fmt.Printf(":: [superinstall] Querying operational indexes for search trace: '%s'\n", query)
	fmt.Println("\n[Native Community Repositories]")
	cmd := exec.Command("pacman", "-Ss", query)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run()

	fmt.Println("\n[Arch User Repository (AUR) Database Index]")
	apiURL := fmt.Sprintf("https://aur.archlinux.org/rpc/?v=5&type=search&arg=%s", url.QueryEscape(query))
	resp, err := pacmanHttpClient.Get(apiURL)
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
}

func (p *PacmanBackend) Validate(pkgName string) bool {
	if strings.HasPrefix(pkgName, "http://") || strings.HasPrefix(pkgName, "https://") || strings.HasSuffix(pkgName, ".git") {
		return true
	}
	checkNative := exec.Command("pacman", "-Si", pkgName)
	if err := checkNative.Run(); err == nil {
		return true
	}
	apiURL := fmt.Sprintf("https://aur.archlinux.org/rpc/?v=5&type=info&arg[]=%s", url.QueryEscape(pkgName))
	resp, err := pacmanHttpClient.Get(apiURL)
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

func (p *PacmanBackend) Install(pkgName string) {
	if strings.HasPrefix(pkgName, "http://") || strings.HasPrefix(pkgName, "https://") || strings.HasSuffix(pkgName, ".git") {
		provider := providers.ResolveGitProvider(pkgName)
		provider.Install(pkgName, "arch")
		return
	}

	isAur, deps := providers.ResolveAURDepsParallel(pkgName)
	if isAur {
		for _, dep := range deps {
			providers.BuildAURPackage(dep)
		}
		return
	}

	args := []string{"pacman", "-S", "--noconfirm", pkgName}
	ExecuteSystemCommand("arch", "sudo", args, false)
}