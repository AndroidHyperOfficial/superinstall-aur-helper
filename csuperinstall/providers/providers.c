#include <stdio.h>
#include <string.h>
#include "providers.h"
#include "aur.h"

// Storing package mappings like the Go RepoMapping dictionary
typedef struct {
    const char *key;
    const char *repo;
} RepoMap;

static RepoMap map_database[] = {
    {"infofetch", "ximi/infofetch"},
    {"ripgrep", "BurntSushi/ripgrep"},
    {"jq", "jqlang/jq"}
};

static int map_size = 3;

void providers_route_install(const char *pkg_name, bool interactive) {
    for (int i = 0; i < map_size; i++) {
        if (strcmp(pkg_name, map_database[i].key) == 0) {
            printf("[Target Discovery] Diverted to repository mapping link: %s\n", map_database[i].repo);
            return;
        }
    }
    install_from_aur(pkg_name, interactive);
}