// auth_derive.c - Mosquitto auth plugin: password = first 23 chars of base64url_no_pad(SHA256(username+secret))
// Build: gcc -fPIC -shared -O2 -I. -o auth_derive.so auth_derive.c -lcrypto
//
// mosquitto.conf example:
// plugin /etc/mosquitto/auth_derive.so
// plugin_opt_secret my-default-secret
// plugin_opt_special alice:alice-secret
// plugin_opt_special bob:bob-secret

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mosquitto.h>
#include "mosquitto_plugin.h"

#include <openssl/sha.h>

#ifndef MOSQ_ERR_AUTH
#define MOSQ_ERR_AUTH 7
#endif

typedef struct {
    char *default_secret;
    struct {
        char *user;
        char *secret;
    } *specials;
    int special_count;
} cfg_t;

static void *xmalloc(size_t n) {
    void *p = malloc(n);
    if(!p) fprintf(stderr, "auth_derive: OOM\n");
    return p;
}

static char *xstrdup(const char *s) {
    if(!s) return NULL;
    size_t n = strlen(s) + 1;
    char *p = (char*)xmalloc(n);
    if(p) memcpy(p, s, n);
    return p;
}

static void free_cfg(cfg_t *cfg) {
    if(!cfg) return;
    free(cfg->default_secret);
    for(int i=0;i<cfg->special_count;i++){
        free(cfg->specials[i].user);
        free(cfg->specials[i].secret);
    }
    free(cfg->specials);
    free(cfg);
}

// constant-time compare for equal-length strings
static int ct_equal(const char *a, const char *b, size_t n) {
    unsigned char diff = 0;
    for(size_t i=0;i<n;i++) diff |= (unsigned char)(a[i] ^ b[i]);
    return diff == 0;
}

static const char *secret_for_user(const cfg_t *cfg, const char *username) {
    if(!cfg || !username) return NULL;
    for(int i=0;i<cfg->special_count;i++){
        if(cfg->specials[i].user && strcmp(cfg->specials[i].user, username) == 0){
            return cfg->specials[i].secret;
        }
    }
    return cfg->default_secret;
}

// base64url (RFC 4648) without padding
static size_t b64url_no_pad(const unsigned char *in, size_t inlen, char *out) {
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t o = 0;
    size_t i = 0;

    while(i + 3 <= inlen){
        unsigned v = (in[i] << 16) | (in[i+1] << 8) | in[i+2];
        out[o++] = T[(v >> 18) & 63];
        out[o++] = T[(v >> 12) & 63];
        out[o++] = T[(v >>  6) & 63];
        out[o++] = T[(v >>  0) & 63];
        i += 3;
    }

    if(inlen - i == 1){
        unsigned v = (in[i] << 16);
        out[o++] = T[(v >> 18) & 63];
        out[o++] = T[(v >> 12) & 63];
        // no padding, so stop (would have been "==")
    } else if(inlen - i == 2){
        unsigned v = (in[i] << 16) | (in[i+1] << 8);
        out[o++] = T[(v >> 18) & 63];
        out[o++] = T[(v >> 12) & 63];
        out[o++] = T[(v >>  6) & 63];
        // no padding, so stop (would have been "=")
    }

    out[o] = '\0';
    return o;
}

// expected password = first 23 chars of base64url_no_pad(SHA256(username + secret))
static int check_password(const char *username, const char *password, const char *secret) {
    if(!username || !password || !secret) return 0;

    const size_t want_len = 23;
    if(strlen(password) != want_len) return 0;

    size_t ulen = strlen(username);
    size_t slen = strlen(secret);
    size_t inlen = ulen + slen;

    unsigned char *buf = (unsigned char*)xmalloc(inlen);
    if(!buf) return 0;
    memcpy(buf, username, ulen);
    memcpy(buf + ulen, secret, slen);

    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(buf, inlen, digest);
    free(buf);

    // SHA256 is 32 bytes => base64url_no_pad length is 43 chars
    char b64[64];
    size_t b64len = b64url_no_pad(digest, SHA256_DIGEST_LENGTH, b64);
    if(b64len < want_len) return 0;

    return ct_equal(password, b64, want_len);
}

int mosquitto_auth_plugin_version(void) {
    return MOSQ_AUTH_PLUGIN_VERSION;
}

int mosquitto_auth_plugin_init(void **user_data, struct mosquitto_opt *opts, int opt_count) {
    cfg_t *cfg = (cfg_t*)calloc(1, sizeof(cfg_t));
    if(!cfg) return MOSQ_ERR_UNKNOWN;

    cfg->default_secret = xstrdup("");

    for(int i=0;i<opt_count;i++){
        const char *k = opts[i].key;
        const char *v = opts[i].value ? opts[i].value : "";

        if(strcmp(k, "secret") == 0) {
            free(cfg->default_secret);
            cfg->default_secret = xstrdup(v);
        } else if(strcmp(k, "special") == 0) {
            // value format: username:secret
            const char *colon = strchr(v, ':');
            if(!colon || colon == v) continue;

            size_t n = (size_t)(colon - v);
            char *user = (char*)xmalloc(n + 1);
            if(!user) continue;
            memcpy(user, v, n);
            user[n] = '\0';

            const char *sec = colon + 1;

            void *tmp = realloc(cfg->specials, sizeof(*cfg->specials) * (cfg->special_count + 1));
            if(!tmp) { free(user); continue; }
            cfg->specials = tmp;

            cfg->specials[cfg->special_count].user = user;
            cfg->specials[cfg->special_count].secret = xstrdup(sec);
            cfg->special_count++;
        }
    }

    *user_data = cfg;
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count) {
    (void)opts; (void)opt_count;
    free_cfg((cfg_t*)user_data);
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_init(void *user_data, struct mosquitto_opt *opts, int opt_count, bool reload) {
    (void)user_data; (void)opts; (void)opt_count; (void)reload;
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count, bool reload) {
    (void)user_data; (void)opts; (void)opt_count; (void)reload;
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_unpwd_check(void *user_data, struct mosquitto *client,
                              const char *username, const char *password) {
    (void)client;
    cfg_t *cfg = (cfg_t*)user_data;

    const char *secret = secret_for_user(cfg, username);
    if(check_password(username, password, secret)) return MOSQ_ERR_SUCCESS;
    return MOSQ_ERR_AUTH;
}
