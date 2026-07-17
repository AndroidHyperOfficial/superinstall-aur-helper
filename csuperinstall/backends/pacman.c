#include <stdio.h>
#include <stdlib.h>
#include "pacman.h"

void pacman_sync() {
    system("sudo pacman -Sy");
}

void pacman_upgrade() {
    system("sudo pacman -Syu");
}

void pacman_uninstall(const char *pkg_name) {
    char rm_cmd[512];
    snprintf(rm_cmd, sizeof(rm_cmd), "sudo pacman -Rns %s --noconfirm", pkg_name);
    system(rm_cmd);
}