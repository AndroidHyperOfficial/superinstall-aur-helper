#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "raylib.h"
#include "backends/backends.h"
#include "backends/pacman.h"
#include "providers/providers.h"
#include "providers/aur.h"

#define VERSION "1.8"

typedef enum { THEME_DARK, THEME_LIGHT, THEME_PURPLE, THEME_BLUE, THEME_RED } ThemeMode;

typedef struct {
    ThemeMode mode;
    Color bgColor1;      
    Color bgColor2;      
    Color panelColor;
    Color textColor;
    Color buttonColor;
    Color buttonHoverColor;
    float buttonRoundness; 
    float buttonSpacing;  
} GUIStyle;

GUIStyle style = {
    .mode = THEME_DARK,
    .bgColor1 = (Color){ 24, 24, 37, 255 },       
    .bgColor2 = (Color){ 24, 24, 37, 255 },
    .panelColor = (Color){ 30, 30, 46, 255 },
    .textColor = (Color){ 205, 214, 244, 255 },
    .buttonColor = (Color){ 137, 180, 250, 255 },
    .buttonHoverColor = (Color){ 116, 199, 236, 255 },
    .buttonRoundness = 0.2f,
    .buttonSpacing = 4.0f
};

// Global buffer to hold search results for drawing in the GUI
char guiSearchResults[2048] = "Repository index ready. Type above and search.";

// Helper to run AUR searches and pipe output straight into the GUI window
void execute_gui_search(const char *query) {
    if (strlen(query) == 0) {
        strcpy(guiSearchResults, "Error: Search query cannot be empty.");
        return;
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "curl -s \"https://aur.archlinux.org/rpc/?v=5&type=search&arg=%s\" | grep -o '\"Name\":\"[^\"]*\"\\|\"Version\":\"[^\"]*\"' | head -n 12 | sed 's/\"//g'", query);
    
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        strcpy(guiSearchResults, "Connection error reaching AUR index databases.");
        return;
    }

    char line[256];
    char name[128] = "";
    char temp_buffer[2048] = "";
    int count = 0;

    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = 0;
        if (strncmp(line, "Name:", 5) == 0) {
            strncpy(name, line + 5, sizeof(name));
        } else if (strncmp(line, "Version:", 8) == 0) {
            char item[256];
            snprintf(item, sizeof(item), "• %s (%s)\n", name, line + 8);
            strncat(temp_buffer, item, sizeof(temp_buffer) - strlen(temp_buffer) - 1);
            count++;
        }
    }
    pclose(fp);

    if (count == 0) {
        snprintf(guiSearchResults, sizeof(guiSearchResults), "No AUR results found matching '%s'.", query);
    } else {
        strncpy(guiSearchResults, temp_buffer, sizeof(guiSearchResults) - 1);
    }
}

void apply_theme(ThemeMode mode) {
    style.mode = mode;
    switch (mode) {
        case THEME_LIGHT:
            style.bgColor1 = (Color){ 240, 240, 245, 255 };
            style.bgColor2 = (Color){ 220, 220, 230, 255 };
            style.panelColor = (Color){ 255, 255, 255, 255 };
            style.textColor = (Color){ 20, 20, 30, 255 };
            style.buttonColor = (Color){ 200, 205, 220, 255 };
            style.buttonHoverColor = (Color){ 180, 185, 200, 255 };
            break;
        case THEME_PURPLE:
            style.bgColor1 = (Color){ 45, 15, 65, 255 };
            style.bgColor2 = (Color){ 15, 5, 25, 255 };
            style.panelColor = (Color){ 70, 30, 95, 200 };
            style.textColor = (Color){ 255, 255, 255, 255 };
            style.buttonColor = (Color){ 140, 80, 220, 255 };
            style.buttonHoverColor = (Color){ 160, 110, 240, 255 };
            break;
        case THEME_BLUE:
            style.bgColor1 = (Color){ 10, 25, 50, 255 };
            style.bgColor2 = (Color){ 5, 10, 25, 255 };
            style.panelColor = (Color){ 20, 45, 85, 200 };
            style.textColor = (Color){ 220, 240, 255, 255 };
            style.buttonColor = (Color){ 40, 110, 210, 255 };
            style.buttonHoverColor = (Color){ 70, 140, 240, 255 };
            break;
        case THEME_RED:
            style.bgColor1 = (Color){ 50, 15, 15, 255 };
            style.bgColor2 = (Color){ 20, 5, 5, 255 };
            style.panelColor = (Color){ 80, 25, 25, 200 };
            style.textColor = (Color){ 255, 220, 220, 255 };
            style.buttonColor = (Color){ 190, 40, 40, 255 };
            style.buttonHoverColor = (Color){ 220, 70, 70, 255 };
            break;
        case THEME_DARK:
        default:
            style.bgColor1 = (Color){ 24, 24, 37, 255 };
            style.bgColor2 = (Color){ 24, 24, 37, 255 };
            style.panelColor = (Color){ 30, 30, 46, 255 };
            style.textColor = (Color){ 205, 214, 244, 255 };
            style.buttonColor = (Color){ 137, 180, 250, 255 };
            style.buttonHoverColor = (Color){ 116, 199, 236, 255 };
            break;
    }
}

bool draw_button_ex(Font font, Rectangle bounds, const char *text) {
    Vector2 mousePos = GetMousePosition();
    bool hovered = CheckCollisionPointRec(mousePos, bounds);
    bool clicked = false;

    Color col = hovered ? style.buttonHoverColor : style.buttonColor;
    if (hovered && IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) clicked = true;

    DrawRectangleRounded(bounds, style.buttonRoundness, 6, col);
    Vector2 textSize = MeasureTextEx(font, text, 18, 1);
    DrawTextEx(font, text, (Vector2){ bounds.x + (bounds.width - textSize.x)/2, bounds.y + (bounds.height - textSize.y)/2 }, 18, 1, style.textColor);
    return clicked;
}

void print_info_logo() {
    printf("\nSUPERinstall!\n");
    printf("-----------------------------------------------\n");
    printf("Platform Architecture:   %s\n", detect_platform());
    printf("Current Version Release: v%s\n", VERSION);
    printf("Built-in System Fetch:   infofetch\n");
    printf("Core Engine Sandbox:     Enabled\n");
    printf("-----------------------------------------------\n\n");
}

void print_usage() {
    printf("Usage: superinstall [options] <arguments>\n\n");
    printf("Commands:\n");
    printf("  -Sy                Update pacman local repositories\n");
    printf("  -Syu               Run full core update and AUR check\n");
    printf("  -S <package>       Scan, secure-audit, and build package\n");
    printf("  -search <query>    Query package name patterns on AUR\n");
    printf("  -info              Dump hardware and software release metadata\n");
    printf("  --clean            Purge local cache trees older than 30 days\n");
    printf("  --gui              Launch hardware accelerated window\n");
}

void launch_gui() {
    InitWindow(500, 700, "Superinstall 1.8 (C & Raylib)");
    SetTargetFPS(60);

    // --- High-Quality Anti-Aliased Font Setup ---
    // Loading at high size (48px) allows scaling down without getting pixelated or blurry
    Font appFont = LoadFontEx("fonts/UbuntuMonoNerdFont-Regular.ttf", 48, NULL, 0);
    if (appFont.texture.id == 0) {
        appFont = LoadFontEx("/usr/share/fonts/liberation/LiberationSans-Regular.ttf", 48, NULL, 0);
    }
    
    // Generate Mipmaps and switch texture sampling mode to Trilinear for pristine vector scaling
    GenTextureMipmaps(&appFont.texture);
    SetTextureFilter(appFont.texture, TEXTURE_FILTER_TRILINEAR);

    char searchBuffer[64] = "";
    int letterCount = 0;
    bool searchActive = false;
    bool showSettings = false;
    char statusMsg[128] = "System Ready. Use search bar above to query repositories.";

    while (!WindowShouldClose()) {
        if (IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
            if (CheckCollisionPointRec(GetMousePosition(), (Rectangle){ 20, 60, 410, 35 })) searchActive = true;
            else searchActive = false;
        }

        if (searchActive) {
            int key = GetCharPressed();
            while (key > 0) {
                if ((key >= 32) && (key <= 125) && (letterCount < 63)) {
                    searchBuffer[letterCount] = (char)key;
                    searchBuffer[letterCount+1] = '\0';
                    letterCount++;
                }
                key = GetCharPressed();
            }
            if (IsKeyPressed(KEY_BACKSPACE) && letterCount > 0) {
                letterCount--;
                searchBuffer[letterCount] = '\0';
            }
        }

        BeginDrawing();
        DrawRectangleGradientV(0, 0, 500, 700, style.bgColor1, style.bgColor2);

        // Header Title
        DrawTextEx(appFont, "Superinstall 1.8", (Vector2){ 155, 20 }, 22, 1, style.textColor);
        if (draw_button_ex(appFont, (Rectangle){ 15, 12, 40, 35 }, "...")) {
            showSettings = !showSettings;
        }

        // Search Input Outline
        DrawRectangleRounded((Rectangle){ 20, 60, 410, 35 }, style.buttonRoundness, 4, style.panelColor);
        DrawRectangleRoundedLines((Rectangle){ 20, 60, 410, 35 }, style.buttonRoundness, 4, searchActive ? style.buttonColor : GRAY);
        
        if (strlen(searchBuffer) == 0) {
            DrawTextEx(appFont, "Search for packages.....", (Vector2){ 30, 68 }, 16, 1, GRAY);
        } else {
            DrawTextEx(appFont, searchBuffer, (Vector2){ 30, 68 }, 16, 1, style.textColor);
        }
        
        if (draw_button_ex(appFont, (Rectangle){ 440, 60, 40, 35 }, ">")) {
            snprintf(statusMsg, sizeof(statusMsg), "Searching AUR for: %s...", searchBuffer);
            execute_gui_search(searchBuffer);
        }

        // Central Logs Box displaying dynamic piped search results
        DrawRectangleRounded((Rectangle){ 20, 110, 460, 430 }, 0.05f, 4, style.panelColor);
        DrawTextEx(appFont, guiSearchResults, (Vector2){ 40, 130 }, 15, 1, style.textColor);

        // Green Bottom Status Container
        DrawRectangle(0, 555, 500, 35, (Color){ 0, 128, 0, 255 });
        Vector2 statusSize = MeasureTextEx(appFont, statusMsg, 14, 1);
        DrawTextEx(appFont, statusMsg, (Vector2){ (500 - statusSize.x) / 2, 563 }, 14, 1, WHITE);

        // Custom Layout Button Spacings
        float sp = style.buttonSpacing;
        float btnW = (460.0f - sp) / 2.0f;
        if (draw_button_ex(appFont, (Rectangle){ 20, 600, btnW, 40 }, "Install")) {
            if (strlen(searchBuffer) > 0) {
                snprintf(statusMsg, sizeof(statusMsg), "Installing %s...", searchBuffer);
                providers_route_install(searchBuffer, false);
            }
        }
        if (draw_button_ex(appFont, (Rectangle){ 20 + btnW + sp, 600, btnW, 40 }, "Downgrade")) {
            snprintf(statusMsg, sizeof(statusMsg), "Checking rollback tables for %s...", searchBuffer);
        }
        if (draw_button_ex(appFont, (Rectangle){ 20, 645 + sp, btnW, 40 }, "Upgrade")) {
            snprintf(statusMsg, sizeof(statusMsg), "Triggering pacman upgrade pipeline...");
            pacman_upgrade();
        }
        if (draw_button_ex(appFont, (Rectangle){ 20 + btnW + sp, 645 + sp, btnW, 40 }, "Uninstall")) {
            if (strlen(searchBuffer) > 0) {
                snprintf(statusMsg, sizeof(statusMsg), "Purging package: %s...", searchBuffer);
                pacman_uninstall(searchBuffer);
            }
        }

        // GUI Options Overlay Panel
        if (showSettings) {
            DrawRectangle(0, 0, 500, 700, (Color){ 0, 0, 0, 180 });
            DrawRectangleRounded((Rectangle){ 50, 100, 400, 480 }, 0.05f, 6, style.panelColor);
            DrawTextEx(appFont, "GUI Customizer Settings", (Vector2){ 110, 120 }, 20, 1, style.textColor);

            DrawTextEx(appFont, "Select Color Theme:", (Vector2){ 70, 165 }, 16, 1, style.textColor);
            if (draw_button_ex(appFont, (Rectangle){ 70, 195, 100, 35 }, "Dark")) apply_theme(THEME_DARK);
            if (draw_button_ex(appFont, (Rectangle){ 180, 195, 100, 35 }, "Light")) apply_theme(THEME_LIGHT);
            if (draw_button_ex(appFont, (Rectangle){ 290, 195, 90, 35 }, "Purple")) apply_theme(THEME_PURPLE);
            if (draw_button_ex(appFont, (Rectangle){ 70, 240, 100, 35 }, "Blue")) apply_theme(THEME_BLUE);
            if (draw_button_ex(appFont, (Rectangle){ 180, 240, 100, 35 }, "Red")) apply_theme(THEME_RED);

            DrawTextEx(appFont, "Button Shape (Corner Roundness):", (Vector2){ 70, 300 }, 16, 1, style.textColor);
            if (draw_button_ex(appFont, (Rectangle){ 70, 330, 150, 35 }, "Sharp (Square)")) style.buttonRoundness = 0.0f;
            if (draw_button_ex(appFont, (Rectangle){ 230, 330, 150, 35 }, "Rounded (Pill)")) style.buttonRoundness = 0.8f;

            DrawTextEx(appFont, "Button Grid Spacing (Offsets):", (Vector2){ 70, 390 }, 16, 1, style.textColor);
            if (draw_button_ex(appFont, (Rectangle){ 70, 420, 80, 35 }, "- Gap")) { if (style.buttonSpacing > 0) style.buttonSpacing -= 2.0f; }
            if (draw_button_ex(appFont, (Rectangle){ 160, 420, 80, 35 }, "+ Gap")) { style.buttonSpacing += 2.0f; }

            if (draw_button_ex(appFont, (Rectangle){ 100, 510, 200, 40 }, "Apply & Close")) showSettings = false;
        }

        EndDrawing();
    }
    
    UnloadFont(appFont);
    CloseWindow();
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage();
        return 0;
    }

    if (strcmp(argv[1], "-info") == 0) {
        print_info_logo();
    } else if (strcmp(argv[1], "-search") == 0 && argc > 2) {
        search_aur(argv[2]);
    } else if (strcmp(argv[1], "-Sy") == 0) {
        pacman_sync();
    } else if (strcmp(argv[1], "-Syu") == 0) {
        pacman_upgrade();
    } else if (strcmp(argv[1], "-S") == 0 && argc > 2) {
        providers_route_install(argv[2], true);
    } else if (strcmp(argv[1], "--clean") == 0) {
        execute_autoclean();
    } else if (strcmp(argv[1], "--gui") == 0) {
        launch_gui();
    } else {
        print_usage();
    }

    return 0;
}