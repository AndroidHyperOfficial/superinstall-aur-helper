#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>
#include "backends.h"

const char* detect_platform() {
#if defined(__aarch64__) || defined(__arm__)
    return "Arch Linux ARM (aarch64/arm)";
#elif defined(__i386__)
    return "Arch Linux 32 (i686)";
#else
    return "Arch Linux Standard (x86_64)";
#endif
}

void execute_autoclean() {
    char cache_root[512];
    snprintf(cache_root, sizeof(cache_root), "%s/.cache/superinstall", getenv("HOME"));
    printf("\x1b[1;32m::\x1b[0m Running cache purification sweep across: %s\n", cache_root);

    DIR *dir = opendir(cache_root);
    if (!dir) {
        printf("\x1b[1;31m[!]\x1b[0m No active cache subfolders detected or accessible.\n");
        return;
    }

    struct dirent *entry;
    time_t now = time(NULL);
    int purged_count = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", cache_root, entry->d_name);
        struct stat st;
        if (stat(path, &st) == 0) {
            if (difftime(now, st.st_mtime) > (30 * 24 * 3600)) {
                printf("  \x1b[1;31m- Expired:\x1b[0m Purging %s\n", entry->d_name);
                char rm_cmd[1100];
                snprintf(rm_cmd, sizeof(rm_cmd), "rm -rf \"%s\"", path);
                system(rm_cmd);
                purged_count++;
            }
        }
    }
    closedir(dir);
    printf("\x1b[1;32m[Success]\x1b[0m Autoclean finalized. Purged %d old source elements.\n", purged_count);
}