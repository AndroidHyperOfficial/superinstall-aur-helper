package providers

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
	"strings"
	"sync"
	"time"
)

var aurHttpClient = &http.Client{Timeout: 6 * time.Second}

func ResolveAURDepsParallel(mainPkg string) (bool, []string) {
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
		resp, err := aurHttpClient.Get(apiURL)
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
				if len(d) == 0 {
					continue
				}
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

func BuildAURPackage(pkg string) {
	tmpDir, err := os.MkdirTemp("", "superinstall-aur-*")
	if err != nil {
		return
	}
	defer os.RemoveAll(tmpDir)

	// REMOVED --single-branch to guarantee Git fetches the repository tracking files correctly
	if err := RunCmdInDir(tmpDir, "git", "clone", "--depth=1", fmt.Sprintf("https://aur.archlinux.org/%s.git", pkg)); err != nil {
		fmt.Printf(":: [superinstall] Failed to clone AUR package: %s\n", pkg)
		return
	}

	targetPkgDir := filepath.Join(tmpDir, pkg)

	// Guard against completely empty repository clones before launching into building
	if !FileExists(filepath.Join(targetPkgDir, "PKGBUILD")) {
		fmt.Printf(":: [superinstall ERROR] Cloned repository '%s' is missing a PKGBUILD file entirely.\n", pkg)
		return
	}

	if !RunSecurityGatekeeper(pkg, targetPkgDir) {
		fmt.Println(":: [superinstall] Safely aborted deployment execution.")
		return
	}

	AttemptInstallationWithPGPFix(targetPkgDir)
}

func AttemptInstallationWithPGPFix(pkgDir string) {
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
					_ = RunCmdInDir(pkgDir, "makepkg", "-si", "--noconfirm", "--needed")
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
			_ = RunCmdInDir(pkgDir, "makepkg", "-si", "--noconfirm", "--needed", "--skippgpcheck")
		}
	}
}