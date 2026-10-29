/* On-screen Wi-Fi setup. See wifi_setup.h. */
#include "wifi_setup.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <psp2/ime_dialog.h>
#include <psp2/libime.h>
#include <vita2d.h>

#include "common.h"

/* --- minimal UTF-8 <-> UTF-16 (BMP) --- */

static void utf8_to_utf16(SceWChar16 *dst, int dstcap, const char *src) {
    int o = 0;
    while (*src && o < dstcap - 1) {
        unsigned char c = (unsigned char)*src;
        unsigned cp;
        if (c < 0x80) { cp = c; src += 1; }
        else if ((c & 0xE0) == 0xC0 && (src[1] & 0xC0) == 0x80) {
            cp = ((c & 0x1F) << 6) | (src[1] & 0x3F); src += 2;
        } else if ((c & 0xF0) == 0xE0 && (src[1] & 0xC0) == 0x80 && (src[2] & 0xC0) == 0x80) {
            cp = ((c & 0x0F) << 12) | ((src[1] & 0x3F) << 6) | (src[2] & 0x3F); src += 3;
        } else { cp = '?'; src += 1; }
        dst[o++] = (SceWChar16)cp;
    }
    dst[o] = 0;
}

static void utf16_to_utf8(char *dst, int dstcap, const SceWChar16 *src) {
    int o = 0;
    while (*src && o < dstcap - 3) {
        unsigned cp = *src++;
        if (cp < 0x80) dst[o++] = (char)cp;
        else if (cp < 0x800) {
            dst[o++] = (char)(0xC0 | (cp >> 6));
            dst[o++] = (char)(0x80 | (cp & 0x3F));
        } else {
            dst[o++] = (char)(0xE0 | (cp >> 12));
            dst[o++] = (char)(0x80 | ((cp >> 6) & 0x3F));
            dst[o++] = (char)(0x80 | (cp & 0x3F));
        }
    }
    dst[o] = 0;
}

bool wifi_prompt(const char *title, const char *initial, char *out, int out_cap, bool password) {
    int max = out_cap - 1;
    if (max > SCE_IME_DIALOG_MAX_TEXT_LENGTH) max = SCE_IME_DIALOG_MAX_TEXT_LENGTH;

    SceWChar16 title16[SCE_IME_DIALOG_MAX_TITLE_LENGTH + 1];
    static SceWChar16 initial16[SCE_IME_DIALOG_MAX_TEXT_LENGTH + 1];
    static SceWChar16 input16[SCE_IME_DIALOG_MAX_TEXT_LENGTH + 1];
    utf8_to_utf16(title16, sizeof(title16) / sizeof(title16[0]), title);
    utf8_to_utf16(initial16, max + 1, initial ? initial : "");
    memset(input16, 0, sizeof(input16));

    SceImeDialogParam param;
    sceImeDialogParamInit(&param);
    param.supportedLanguages = SCE_IME_LANGUAGE_ENGLISH;
    param.type = SCE_IME_TYPE_BASIC_LATIN;
    param.dialogMode = SCE_IME_DIALOG_DIALOG_MODE_WITH_CANCEL;
    param.textBoxMode = password ? SCE_IME_DIALOG_TEXTBOX_MODE_PASSWORD
                                  : SCE_IME_DIALOG_TEXTBOX_MODE_WITH_CLEAR;
    param.title = title16;
    param.maxTextLength = (SceUInt32)max;
    param.initialText = initial16;
    param.inputTextBuffer = input16;
    if (sceImeDialogInit(&param) < 0) return false;

    for (;;) {
        vita2d_start_drawing();
        vita2d_clear_screen();
        vita2d_end_drawing();
        vita2d_common_dialog_update();
        vita2d_swap_buffers();
        if (sceImeDialogGetStatus() == SCE_COMMON_DIALOG_STATUS_FINISHED) break;
    }

    SceImeDialogResult result;
    memset(&result, 0, sizeof(result));
    sceImeDialogGetResult(&result);
    bool confirmed = result.button == SCE_IME_DIALOG_BUTTON_ENTER;
    if (confirmed) utf16_to_utf8(out, out_cap, input16);
    sceImeDialogTerm();
    return confirmed;
}

void wifi_save_config(void) {
    char path[128];
    snprintf(path, sizeof(path), "%s/config.txt", APP_DIR);

    /* Read the existing file, dropping any wifi_ssid= / wifi_pass= lines (we rewrite those). */
    char *kept = malloc(8192);
    int kept_len = 0;
    if (kept) {
        kept[0] = 0;
        FILE *f = fopen(path, "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                if (strncmp(line, "wifi_ssid=", 10) == 0 || strncmp(line, "wifi_pass=", 10) == 0)
                    continue;
                int n = (int)strlen(line);
                if (kept_len + n < 8192 - 1) { memcpy(kept + kept_len, line, n); kept_len += n; kept[kept_len] = 0; }
            }
            fclose(f);
        }
    }

    FILE *f = fopen(path, "w");
    if (!f) { free(kept); return; }
    if (kept && kept_len > 0) {
        fwrite(kept, 1, kept_len, f);
        if (kept[kept_len - 1] != '\n') fputc('\n', f);
    }
    fprintf(f, "wifi_ssid=%s\n", g_config.wifi_ssid);
    fprintf(f, "wifi_pass=%s\n", g_config.wifi_pass);
    fclose(f);
    free(kept);
    vp_log("Wi-Fi settings saved (ssid=%s, password %s)", g_config.wifi_ssid,
           g_config.wifi_pass[0] ? "set" : "empty");
}
