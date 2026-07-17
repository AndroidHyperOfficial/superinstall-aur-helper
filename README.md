# superinstall (v1.8 C & Raylib Port)

This is a lightweight, security-focused package manager helper designed for Arch Linux. Originally written in Go, this version is a complete rewrite in native C. It uses Raylib for basic hardware-accelerated GUI layouts, resulting in an exceptionally small footprint of only ~26 KB.

---

## Build and Setup

To compile and install the application locally, you will need gcc, raylib, and the X11 development headers installed on your system by typing this command:
```bash
sudo pacman -S git curl gnupg raylib libx11
```
Follow these steps to clone, navigate the directories, compile the binary directly to your user's local path, and run it globally.

### Clone the Repo
```bash
git clone https://github.com/AndroidHyperOfficial/superinstall-aur-helper.git
```
### Navigate to Source Path
```bash
cd superinstall-aur-helper
cd csuperinstall
```
### Compile
```bash
gcc main.c \
    backends/backends.c \
    backends/pacman.c \
    providers/providers.c \
    providers/aur.c \
    -o ~/.local/bin/superinstall \
    -O3 \
    -lraylib -lGL -lm -lpthread -ldl -lrt -lX11
  ```
### Lanuch it NOW
    superinstall
