# superinstall-aur-helper
A security-focused CLI package manager alternative to paru and yay for Arch Linux users.
## FEATURES
* **Unified Management**: Seamlessly handles system repositories and the AUR in one interface.
* **Security Auditor**: Built-in heuristic scanner that inspects build scripts for malicious patterns before execution.
* **PGP Self-Healing**: Automatically fetches developer keys and verifies identities to prevent build failures.
## Known Risks & Limitations
* **Dependency Conflict Risks**: Unlike `pacman` or `paru`, this tool's parallel resolver focuses on speed and does not perform deep validation of complex `provides`/`conflicts` tags, which may lead to dependency issues in complex AUR packages.
* **Maintenance Overhead**: As a custom-built helper, users are responsible for ensuring the tool stays compatible with upstream Arch Linux API changes or `pacman` metadata updates.
* **Security "Trust" Paradox**: The PGP Self-Healing feature automates trust decisions; users should remain vigilant and verify PGP identities when prompted, rather than relying solely on automation.
* **Manual "Heavy Lifting" Backup**: It is highly recommended to keep `pacman` or `paru` installed for mission-critical system updates, as this tool is primarily optimized for daily utility and application management.
## Installation
First, ensure you have **Go** and **Git** and **7zip** installed on your system using your native package manager:
```bash
sudo pacman -S git go 7zip
```
### Setup
Once the prerequisites are installed, clone the repository and run the self-installer:
```bash
git clone https://github.com/AndroidHyperOfficial/superinstall-aur-helper.git
cd superinstall-aur-helper
unzip superinstall.zip
cd superinstall
export GO111MODULE=on
go run main.go --install-self
```
### Linux: The tool automatically attempts to place the binary in your system path; if you receive a "Permission Denied" error, try running go run main.go --install-self with sudo.
