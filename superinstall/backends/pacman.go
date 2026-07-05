package backends

import (
	"os"
	"os/exec"
)

// RunPacman executes standard pacman commands with elevated privileges
func RunPacman(args ...string) error {
	fullArgs := append([]string{"pacman"}, args...)
	cmd := exec.Command("sudo", fullArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}