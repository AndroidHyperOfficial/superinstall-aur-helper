# superinstall-aur-helper
A security-focused CLI package manager alternative to paru and yay for Arch Linux users.
## FEATURES
* **Unified Management**: Seamlessly handles system repositories and the AUR in one interface.
* **Security Auditor**: Built-in heuristic scanner that inspects build scripts for malicious patterns before execution.
* **PGP Self-Healing**: Automatically fetches developer keys and verifies identities to prevent build failures.
* **7-Day Auto-Update**: Includes a self-maintenance engine that automatically keeps your installation current.
## Compatibility & Limitations

`superinstall` is designed primarily for Arch Linux, where it functions as a native AUR helper. Its behavior changes depending on the operating system:

* **Arch Linux**: Acts as a full-featured AUR helper with parallel dependency resolution and PGP self-healing.
* **Other Platforms (Windows, macOS, BSD, Linux Distros)**: Functions as a unified wrapper. It detects your native package manager (like `winget`, `brew`, or `apt`) and routes commands through it to provide a consistent CLI experience.

### Known Limitations
* **Wrapper Fragility**: On non-Arch platforms, the tool relies on your system's native package manager. If the native tool's command syntax changes, `superinstall` may require an update to maintain compatibility.
* **Path Management**: The tool assumes standard environment paths (e.g., `/usr/local/bin` or system defaults). Custom installation setups may require manual path configuration.
* **Arch-Specific Logic**: Features like the "Security Gatekeeper" and "PGP Self-Healing" are optimized for Arch-based workflows and may have limited functionality on other operating systems.
## Arch Linux: Known Risks & Limitations
While `superinstall` provides a streamlined interface for Arch, users should be aware of these architectural trade-offs:

* **Dependency Conflict Risks**: Unlike `pacman` or `paru`, this tool's parallel resolver focuses on speed and does not perform deep validation of complex `provides`/`conflicts` tags, which may lead to dependency issues in complex AUR packages.
* **Maintenance Overhead**: As a custom-built helper, users are responsible for ensuring the tool stays compatible with upstream Arch Linux API changes or `pacman` metadata updates.
* **Security "Trust" Paradox**: The PGP Self-Healing feature automates trust decisions; users should remain vigilant and verify PGP identities when prompted, rather than relying solely on automation.
* **Manual "Heavy Lifting" Backup**: It is highly recommended to keep `pacman` or `paru` installed for mission-critical system updates, as this tool is primarily optimized for daily utility and application management.
## Installation
First, ensure you have **Go** and **Git** installed on your system using your native package manager:

**Arch Linux**
```bash
sudo pacman -S git go
```
**Fedora and Red Hat**
```bash
sudo dnf install goland git
```
**Linux Gentoo (GO TOUCH GRASS NO JUST KIDDING)**
```bash
sudo emerge dev-lang/go dev-vcs/git
```
**MacOS**
```bash
brew install git go
```
**Debian and Ubuntu and Mint and other debian-based distros**
```bash
sudo apt install golang git
```
**FreeBSD**
```bash
pkg install sudo (i like sudo lol)
sudo pkg install go git
```
**Windows (i hate microslop)**
```bash
winget install GoLang.Go Git.Git
```
### Setup
Once the prerequisites are installed, clone the repository and run the self-installer:
```bash
git clone https://github.com/AndroidHyperOfficial/superinstall-aur-helper.git
cd superinstall-aur-helper
cd superinstall
go run main.go --install-self
```
## OS-Specific Notes
### Windows: After running --install-self, you may need to restart your terminal or open a new session for the binary path to be recognized in your environment variables.
### Gentoo & BSD: Ensure your user has write permissions to the destination directory for the binary (typically /usr/local/bin).
### macOS/Linux: The tool automatically attempts to place the binary in your system path; if you receive a "Permission Denied" error, try running go run main.go --install-self with sudo.
