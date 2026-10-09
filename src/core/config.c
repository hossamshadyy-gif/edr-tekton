/*
 * edr-tekton :: Configuration Parser
 * Lightweight YAML subset parser for profile files.
 * Handles the flat key:value and nested map structures
 * used in EDR profiles.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "tekton/core/config.h"
#include "tekton/core/log.h"

/* ── Internal helpers ─────────────────────────────────── */

static void trim_whitespace(char* str) {
    /* Trim leading */
    char* start = str;
    while (*start && isspace((unsigned char)*start)) start++;
    if (start != str) memmove(str, start, strlen(start) + 1);

    /* Trim trailing */
    size_t len = strlen(str);
    while (len > 0 && isspace((unsigned char)str[len - 1])) {
        str[--len] = '\0';
    }
}

static int get_indent_level(const char* line) {
    int indent = 0;
    while (*line == ' ') { indent++; line++; }
    return indent / 2;  /* 2-space indentation standard */
}

static BOOL is_comment_or_empty(const char* line) {
    while (*line && isspace((unsigned char)*line)) line++;
    return (*line == '#' || *line == '\0' || *line == '\n');
}

static PTEKTON_CFG_NODE cfg_node_create(void) {
    PTEKTON_CFG_NODE node = (PTEKTON_CFG_NODE)calloc(1, sizeof(TEKTON_CFG_NODE));
    return node;
}

static void cfg_node_free(PTEKTON_CFG_NODE node) {
    if (!node) return;
    for (DWORD i = 0; i < node->child_count; i++) {
        cfg_node_free(node->children[i]);
    }
    free(node);
}

static PTEKTON_CFG_NODE cfg_node_add_child(PTEKTON_CFG_NODE parent) {
    if (!parent || parent->child_count >= TEKTON_CFG_MAX_CHILDREN) return NULL;
    PTEKTON_CFG_NODE child = cfg_node_create();
    if (!child) return NULL;
    child->parent = parent;
    parent->children[parent->child_count++] = child;
    return child;
}

/* ── YAML Subset Parser ──────────────────────────────── */

static TEKTON_STATUS parse_yaml_lines(
    const char*     yaml,
    SIZE_T          yaml_len,
    PTEKTON_CFG_NODE root
) {
    const char* pos = yaml;
    const char* end = yaml + yaml_len;

    /* Stack of nodes at each indent level */
    PTEKTON_CFG_NODE stack[32];
    int stack_depth = 0;
    stack[0] = root;

    char line_buf[1024];

    while (pos < end) {
        /* Read one line */
        const char* line_end = pos;
        while (line_end < end && *line_end != '\n') line_end++;

        size_t line_len = (size_t)(line_end - pos);
        if (line_len >= sizeof(line_buf)) line_len = sizeof(line_buf) - 1;
        memcpy(line_buf, pos, line_len);
        line_buf[line_len] = '\0';

        pos = line_end + 1;

        /* Skip comments and empty lines */
        if (is_comment_or_empty(line_buf)) continue;

        int indent = get_indent_level(line_buf);
        trim_whitespace(line_buf);

        /* Parse "key: value" or "- item" */
        char* colon = strchr(line_buf, ':');
        BOOL is_list_item = (line_buf[0] == '-');

        if (is_list_item) {
            /* List item: "- value" */
            char* value = line_buf + 1;
            while (*value && isspace((unsigned char)*value)) value++;

            /* Find parent at correct indent level */
            while (stack_depth > indent && stack_depth > 0) stack_depth--;

            PTEKTON_CFG_NODE item = cfg_node_add_child(stack[stack_depth]);
            if (!item) continue;

            item->type = TEKTON_CFG_STRING;
            snprintf(item->value, TEKTON_CFG_MAX_VALUE, "%s", value);

            /* Check if list item has nested map (e.g., "- { type: xor }") */
            if (value[0] == '{') {
                item->type = TEKTON_CFG_MAP;
                /* Parse inline map */
                char* p = value + 1;
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

                        PTEKTON_CFG_NODE field = cfg_node_add_child(item);
                        if (field) {
                            trim_whitespace(k);
                            trim_whitespace(v);
                            snprintf(field->key, TEKTON_CFG_MAX_KEY, "%s", k);
                            snprintf(field->value, TEKTON_CFG_MAX_VALUE, "%s", v);
                            field->type = TEKTON_CFG_STRING;
                        }
                        if (saved == '}') break;
                    } else break;
                }
            }
        } else if (colon) {
            /* Key: value pair */
            *colon = '\0';
            char* key = line_buf;
            char* value = colon + 1;
            trim_whitespace(key);
            trim_whitespace(value);

            /* Find parent at correct indent level */
            while (stack_depth > indent && stack_depth > 0) stack_depth--;

            PTEKTON_CFG_NODE node = cfg_node_add_child(stack[stack_depth]);
            if (!node) continue;

            snprintf(node->key, TEKTON_CFG_MAX_KEY, "%s", key);

            if (value[0] == '\0') {
                /* No value = map node */
                node->type = TEKTON_CFG_MAP;
                /* Push onto stack for nested children */
                if (indent + 1 < 32) {
                    stack[indent + 1] = node;
                    stack_depth = indent + 1;
                }
            } else if (value[0] == '[') {
                /* Inline list: [a, b, c] */
                node->type = TEKTON_CFG_LIST;
                snprintf(node->value, TEKTON_CFG_MAX_VALUE, "%s", value);

                /* Parse items */
                char* p = value + 1;
                while (*p && *p != ']') {
                    while (*p && isspace((unsigned char)*p)) p++;
                    char* item_start = p;
                    while (*p && *p != ',' && *p != ']') p++;
                    char saved = *p;
                    *p = '\0';

                    PTEKTON_CFG_NODE child = cfg_node_add_child(node);
                    if (child) {
                        trim_whitespace(item_start);
                        snprintf(child->value, TEKTON_CFG_MAX_VALUE, "%s", item_start);
                        child->type = TEKTON_CFG_STRING;
                    }

                    if (saved == ']') break;
                    if (saved == ',') p++;
                }
            } else {
                /* Simple string value */
                node->type = TEKTON_CFG_STRING;
                snprintf(node->value, TEKTON_CFG_MAX_VALUE, "%s", value);
            }
        }
    }

    return TEKTON_OK;
}

/* ── Find node by dotted path ─────────────────────────── */

static PTEKTON_CFG_NODE cfg_find_node(PTEKTON_CFG_NODE root, const char* path) {
    if (!root || !path) return NULL;

    char path_copy[512];
    snprintf(path_copy, sizeof(path_copy), "%s", path);

    PTEKTON_CFG_NODE current = root;
    char* token = strtok(path_copy, ".");

    while (token && current) {
        BOOL found = FALSE;
        for (DWORD i = 0; i < current->child_count; i++) {
            if (strcmp(current->children[i]->key, token) == 0) {
                current = current->children[i];
                found = TRUE;
                break;
            }
        }
        if (!found) return NULL;
        token = strtok(NULL, ".");
    }

    return current;
}

/* ── Public API ───────────────────────────────────────── */

TEKTON_STATUS TektonConfigLoad(const char* profile_path, PTEKTON_CONFIG out_config) {
    if (!profile_path || !out_config) return TEKTON_ERR_INVALID_PARAM;

    FILE* fp = fopen(profile_path, "rb");
    if (!fp) {
        TLOG_ERROR("Cannot open profile: %s", profile_path);
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

    size_t read = fread(yaml, 1, (size_t)size, fp);
    yaml[read] = '\0';
    fclose(fp);

    TEKTON_STATUS status = TektonConfigParse(yaml, read, out_config);
    free(yaml);
    return status;
}

TEKTON_STATUS TektonConfigParse(
    const char*     yaml_string,
    SIZE_T          yaml_length,
    PTEKTON_CONFIG  out_config
) {
    if (!yaml_string || !out_config) return TEKTON_ERR_INVALID_PARAM;

    memset(out_config, 0, sizeof(TEKTON_CONFIG));

    /* Create root node */
    out_config->root = cfg_node_create();
    if (!out_config->root) return TEKTON_ERR_ALLOC;
    out_config->root->type = TEKTON_CFG_MAP;

    /* Parse YAML into tree */
    TEKTON_STATUS status = parse_yaml_lines(yaml_string, yaml_length, out_config->root);
    if (status != TEKTON_OK) {
        cfg_node_free(out_config->root);
        out_config->root = NULL;
        return status;
    }

    /* ── Extract known fields ────────────────────────── */

    const char* val;

    val = TektonConfigGet(out_config, "profile");
    if (val) snprintf(out_config->profile_name, sizeof(out_config->profile_name), "%s", val);

    val = TektonConfigGet(out_config, "version");
    if (val) snprintf(out_config->profile_version, sizeof(out_config->profile_version), "%s", val);

    val = TektonConfigGet(out_config, "target.edr");
    if (val) snprintf(out_config->target_edr, sizeof(out_config->target_edr), "%s", val);

    out_config->target_os_build = (DWORD)TektonConfigGetInt(out_config, "target.os_build", 0);

    val = TektonConfigGet(out_config, "target.arch");
    if (val) snprintf(out_config->target_arch, sizeof(out_config->target_arch), "%s", val);

    /* Pipeline */
    val = TektonConfigGet(out_config, "pipeline.api_resolve");
    if (val) snprintf(out_config->api_resolve, sizeof(out_config->api_resolve), "%s", val);

    val = TektonConfigGet(out_config, "pipeline.syscall.method");
    if (val) snprintf(out_config->syscall_method, sizeof(out_config->syscall_method), "%s", val);

    val = TektonConfigGet(out_config, "pipeline.syscall.ssn_resolve");
    if (val) snprintf(out_config->ssn_resolve, sizeof(out_config->ssn_resolve), "%s", val);

    val = TektonConfigGet(out_config, "pipeline.syscall.callstack");
    if (val) snprintf(out_config->callstack_spoof, sizeof(out_config->callstack_spoof), "%s", val);

    val = TektonConfigGet(out_config, "pipeline.inject.method");
    if (val) snprintf(out_config->inject_method, sizeof(out_config->inject_method), "%s", val);

    val = TektonConfigGet(out_config, "pipeline.inject.target_process");
    if (val) snprintf(out_config->inject_target, sizeof(out_config->inject_target), "%s", val);

    val = TektonConfigGet(out_config, "pipeline.evasion.etw");
    if (val) snprintf(out_config->etw_method, sizeof(out_config->etw_method), "%s", val);

    val = TektonConfigGet(out_config, "pipeline.evasion.amsi");
    if (val) snprintf(out_config->amsi_method, sizeof(out_config->amsi_method), "%s", val);

    val = TektonConfigGet(out_config, "pipeline.sleep.method");
    if (val) snprintf(out_config->sleep_method, sizeof(out_config->sleep_method), "%s", val);

    out_config->sleep_interval_ms = (DWORD)TektonConfigGetInt(out_config, "pipeline.sleep.interval_ms", 30000);

    val = TektonConfigGet(out_config, "payload.source");
    if (val) snprintf(out_config->payload_path, sizeof(out_config->payload_path), "%s", val);

    val = TektonConfigGet(out_config, "payload.format");
    if (val) snprintf(out_config->payload_format, sizeof(out_config->payload_format), "%s", val);

    /* Sandbox checks (inline list) */
    PTEKTON_CFG_NODE sandbox_node = cfg_find_node(out_config->root, "pipeline.evasion.sandbox.checks");
    if (sandbox_node) {
        for (DWORD i = 0; i < sandbox_node->child_count && i < TEKTON_MAX_SANDBOX_CHECKS; i++) {
            snprintf(out_config->sandbox_checks[i],
                sizeof(out_config->sandbox_checks[0]),
                "%s", sandbox_node->children[i]->value);
            out_config->sandbox_check_count++;
        }
    }

    /* Encryption layers */
    PTEKTON_CFG_NODE layers_node = cfg_find_node(out_config->root, "pipeline.encrypt.layers");
    if (layers_node) {
        for (DWORD i = 0; i < layers_node->child_count && i < TEKTON_MAX_ENCRYPT_LAYERS; i++) {
            PTEKTON_CFG_NODE layer = layers_node->children[i];
            PTEKTON_ENCRYPT_LAYER cfg_layer = &out_config->encrypt_layers[out_config->encrypt_layer_count];

            for (DWORD j = 0; j < layer->child_count; j++) {
                if (strcmp(layer->children[j]->key, "type") == 0) {
                    snprintf(cfg_layer->type, sizeof(cfg_layer->type), "%s", layer->children[j]->value);
                } else if (strcmp(layer->children[j]->key, "key_source") == 0) {
                    snprintf(cfg_layer->key_source, sizeof(cfg_layer->key_source), "%s", layer->children[j]->value);
                }
            }

            out_config->encrypt_layer_count++;
        }
    }

    TLOG_INFO("Config loaded: profile=%s edr=%s arch=%s",
        out_config->profile_name,
        out_config->target_edr,
        out_config->target_arch);

    return TEKTON_OK;
}

const char* TektonConfigGet(PTEKTON_CONFIG config, const char* path) {
    if (!config || !config->root || !path) return NULL;

    PTEKTON_CFG_NODE node = cfg_find_node(config->root, path);
    if (!node) return NULL;
    if (node->value[0] == '\0') return NULL;

    return node->value;
}

int TektonConfigGetInt(PTEKTON_CONFIG config, const char* path, int default_val) {
    const char* val = TektonConfigGet(config, path);
    if (!val) return default_val;
    return atoi(val);
}

BOOL TektonConfigGetBool(PTEKTON_CONFIG config, const char* path, BOOL default_val) {
    const char* val = TektonConfigGet(config, path);
    if (!val) return default_val;
    return (strcmp(val, "true") == 0 || strcmp(val, "yes") == 0 || strcmp(val, "1") == 0);
}

VOID TektonConfigFree(PTEKTON_CONFIG config) {
    if (!config) return;
    if (config->root) {
        cfg_node_free(config->root);
        config->root = NULL;
    }
}
