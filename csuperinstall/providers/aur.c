#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/stat.h>
#include "aur.h"

#define WEIGHT_NETWORK_DROP 40
#define WEIGHT_OBFUSCATION 35
#define WEIGHT_SYSTEM_WIPE 50
#define WEIGHT_PERSISTENCE 30

void run_pgp_healing(const char *pkgbuild_path) {
    printf("\x1b[1;34m:: [PGP Self-Healing]\x1b[0m Parsing recipe context for cryptographic developer keys...\n");
    FILE *file = fopen(pkgbuild_path, "r");
    if (!file) return;

    char line[512];
    while (fgets(line, sizeof(line), file)) {
        if (strstr(line, "validpgpkeys=") != NULL) {
            char *start = strchr(line, '(');
            char *end = strchr(line, ')');
            if (start && end) {
                *end = '\0';
                char *token = strtok(start + 1, " '\"\n\r");
                while (token != NULL) {
                    if (strlen(token) > 8) {
                        printf("  \x1b[1;32m->\x1b[0m Recovering cryptographic signature key: %s\n", token);
                        char cmd[256];
                        snprintf(cmd, sizeof(cmd), "gpg --recv-keys %s > /dev/null 2>&1", token);
                        system(cmd);
                    }
                    token = strtok(NULL, " '\"\n\r");
                }
            }
        }
    }
    fclose(file);
}

bool run_security_audit(const char *pkg_name, const char *pkgbuild_path, bool interactive) {
    printf("\x1b[1;33m:: [Security Auditor]\x1b[0m Commencing structural heuristic validation for \x1b[1;37m%s\x1b[0m...\n", pkg_name);
    
    FILE *file = fopen(pkgbuild_path, "r");
    if (!file) {
        printf("\x1b[1;31m[!] Error:\x1b[0m Unable to open build recipe target for auditing.\n");
        return false;
    }

    int total_risk_score = 0;
    char line[512];
    int line_count = 0;
    int threats_found = 0;

    while (fgets(line, sizeof(line), file)) {
        line_count++;
        if (line[0] == '\n' || line[0] == '#') continue;

        if (strstr(line, "base64 -d") != NULL && (strstr(line, "| sh") != NULL || strstr(line, "| bash") != NULL)) {
            printf("  \x1b[1;31m[Line %d]\x1b[0m Obfuscated payload pipe execution detected.\n", line_count);
            total_risk_score += WEIGHT_OBFUSCATION;
            threats_found++;
        }
        if (strstr(line, "rm ") != NULL && strstr(line, "-rf") != NULL) {
            if (strstr(line, " /") != NULL || strstr(line, "$srcdir/../../") != NULL || strstr(line, "rm -rf /") != NULL) {
                printf("  \x1b[1;31m[Line %d]\x1b[0m Dangerous destructive system wipe path detected.\n", line_count);
                total_risk_score += WEIGHT_SYSTEM_WIPE;
                threats_found++;
            }
        }
        if ((strstr(line, "curl") != NULL || strstr(line, "wget") != NULL) && (strstr(line, "| bash") != NULL || strstr(line, "| sh") != NULL)) {
            printf("  \x1b[1;31m[Line %d]\x1b[0m Suspicious interactive outbound network pipe execution.\n", line_count);
            total_risk_score += WEIGHT_NETWORK_DROP;
            threats_found++;
        }
        if (strstr(line, ".service") != NULL && strstr(line, "/etc/systemd/") != NULL) {
            printf("  \x1b[1;31m[Line %d]\x1b[0m Unauthorized persistence service injection flagged.\n", line_count);
            total_risk_score += WEIGHT_PERSISTENCE;
            threats_found++;
        }
        if ((strstr(line, "/etc/") != NULL || strstr(line, "/usr/bin/") != NULL || strstr(line, "/boot/") != NULL) && 
            strstr(line, "$pkgdir") == NULL && strstr(line, "${pkgdir}") == NULL) {
            printf("  \x1b[1;33m[Line %d]\x1b[0m Out-of-sandbox target system folder modification.\n", line_count);
            total_risk_score += 5;
            threats_found++;
        }
    }
    fclose(file);

    if (threats_found == 0) {
        printf("  \x1b[1;32m✓\x1b[0m Security Audit Passed: No suspicious execution paths or sandbox violations found.\n");
        return true;
    }

    printf("\n\x1b[1;31m[Risk Evaluation Level: %d/100]\x1b[0m\n", total_risk_score);

    if (total_risk_score >= 50) {
        printf("\n\x1b[1;31m[CRITICAL]\x1b[0m Package behaviors match signature elements of historical supply-chain attacks. Dropping pipeline.\n");
        return false;
    }

    if (!interactive) return true;

    printf("Proceed with native script installation? [y/N]: ");
    char choice[16];
    if (fgets(choice, sizeof(choice), stdin)) {
        if (choice[0] == 'y' || choice[0] == 'Y') return true;
    }
    return false;
}

void review_pkgbuild_safely(const char *pkg_name, const char *filepath) {
    printf("\n\x1b[1;33m[Review Prompt]\x1b[0m Would you like to view the PKGBUILD for '%s'? [Y/n]: ", pkg_name);
    char response[16];
    if (!fgets(response, sizeof(response), stdin)) return;
    if (response[0] == 'n' || response[0] == 'N') return;

    FILE *file = fopen(filepath, "r");
    if (!file) {
        printf("Error: Could not read PKGBUILD file at %s\n", filepath);
        return;
    }

    printf("\n--- PKGBUILD Reader (Press ENTER to scroll, type 'q' and press ENTER to exit safely) ---\n\n");
    char line[512];
    int line_count = 0;
    while (fgets(line, sizeof(line), file)) {
        printf("%s", line);
        line_count++;
        
        if (line_count % 24 == 0) {
            printf("\x1b[1;33m-- More (Press Enter to continue, 'q' to quit) --\x1b[0m");
            char choice[16];
            if (fgets(choice, sizeof(choice), stdin)) {
                if (choice[0] == 'q' || choice[0] == 'Q') break;
            }
        }
    }
    fclose(file);
    printf("\n--- End of PKGBUILD review ---\n\n");
}

void search_aur(const char *query) {
    printf("\x1b[1;32m->\x1b[0m Querying global AUR metadata indexes for '%s'...\n\n", query);
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "curl -s \"https://aur.archlinux.org/rpc/?v=5&type=search&arg=%s\" | grep -o '\"Name\":\"[^\"]*\"\\|\"Version\":\"[^\"]*\"\\|\"Description\":\"[^\"]*\"' | sed 's/\"//g'", query);
    
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        printf("Error reaching upstream AUR index streams.\n");
        return;
    }

    char line[256];
    char name[128] = "";
    char version[128] = "";
    int count = 0;

    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = 0;
        if (strncmp(line, "Name:", 5) == 0) {
            strncpy(name, line + 5, sizeof(name));
        } else if (strncmp(line, "Version:", 8) == 0) {
            strncpy(version, line + 8, sizeof(version));
        } else if (strncmp(line, "Description:", 12) == 0) {
            printf("\x1b[1;35maur/\x1b[1;37m%s \x1b[1;32m%s\x1b[0m\n    %s\n", name, version, line + 12);
            count++;
        }
    }
    pclose(fp);

    if (count == 0) printf("No matching AUR recipe matrix entries found for '%s'.\n", query);
}

int install_from_aur(const char *pkg_name, bool interactive) {
    printf("\x1b[1;32m::\x1b[0m Resolving configuration maps for: '%s'...\n", pkg_name);

    char cache_dir[512];
    snprintf(cache_dir, sizeof(cache_dir), "%s/.cache/superinstall/%s", getenv("HOME"), pkg_name);
    
    char mkdir_cmd[512];
    snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p \"%s\" && rm -rf \"%s\"/*", cache_dir, cache_dir);
    system(mkdir_cmd);

    printf("\x1b[1;34m->\x1b[0m Cloning source tree from: https://aur.archlinux.org/%s.git\n", pkg_name);
    char clone_cmd[1024];
    snprintf(clone_cmd, sizeof(clone_cmd), "git clone https://aur.archlinux.org/%s.git \"%s\"", pkg_name, cache_dir);
    if (system(clone_cmd) != 0) {
        printf("\x1b[1;31mError:\x1b[0m Failed to pull git source mapping for %s.\n", pkg_name);
        return 1;
    }

    char pkgbuild_path[1024];
    snprintf(pkgbuild_path, sizeof(pkgbuild_path), "%s/PKGBUILD", cache_dir);
    
    if (interactive) {
        review_pkgbuild_safely(pkg_name, pkgbuild_path);
    }

    if (!run_security_audit(pkg_name, pkgbuild_path, interactive)) {
        printf("\x1b[1;31mError:\x1b[0m Installation aborted due to security flag warnings.\n");
        return 1;
    }

    run_pgp_healing(pkgbuild_path);

    printf("\x1b[1;32m::\x1b[0m Starting compilation layout via makepkg...\n");
    char build_cmd[1024];
    snprintf(build_cmd, sizeof(build_cmd), "cd \"%s\" && makepkg -si -A --noconfirm", cache_dir);
    
    if (system(build_cmd) != 0) {
        printf("\x1b[1;31mError:\x1b[0m Build pipeline processing failed for '%s'.\n", pkg_name);
        return 1;
    }

    printf("\n\x1b[1;32m[Success]\x1b[0m Natively deployed '%s' seamlessly!\n", pkg_name);
    return 0;
}