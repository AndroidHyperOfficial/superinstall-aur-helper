package providers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
)

type AurResponse struct {
	ResultCount int          `json:"resultcount"`
	Results     []AurPackage `json:"results"`
}

type AurPackage struct {
	Name        string `json:"Name"`
	PackageBase string `json:"PackageBase"`
}

// CheckAUR queries the Arch User Repository RPC v5 endpoint
func CheckAUR(pkg string) (bool, error) {
	apiURL := fmt.Sprintf("https://aur.archlinux.org/rpc/?v=5&type=info&arg[]=%s", url.QueryEscape(pkg))
	resp, err := http.Get(apiURL)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var aurResp AurResponse
	if err := json.NewDecoder(resp.Body).Decode(&aurResp); err != nil {
		return false, err
	}

	return aurResp.ResultCount > 0, nil
}

// InstallAUR clones the PKGBUILD repository into a temp dir and compiles it
func InstallAUR(pkg string) error {
	tmpDir, err := os.MkdirTemp("", "superinstall-build-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	gitURL := fmt.Sprintf("https://aur.archlinux.org/%s.git", pkg)
	fmt.Printf(":: [superinstall] Cloning %s into %s...\n", gitURL, tmpDir)

	if err := runCmd(tmpDir, "git", "clone", gitURL); err != nil {
		return fmt.Errorf("git clone failed: %w", err)
	}

	pkgDir := filepath.Join(tmpDir, pkg)
	fmt.Println(":: [superinstall] Running makepkg -si...")
	return runCmd(pkgDir, "makepkg", "-si")
}

func runCmd(dir string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}