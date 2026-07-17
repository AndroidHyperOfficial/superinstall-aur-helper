#ifndef AUR_H
#define AUR_H
#include <stdbool.h>

void search_aur(const char *query);
int install_from_aur(const char *pkg_name, bool interactive);
void run_pgp_healing(const char *pkgbuild_path);
bool run_security_audit(const char *pkg_name, const char *pkgbuild_path, bool interactive);

#endif