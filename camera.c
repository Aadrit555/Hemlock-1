#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image_write.h"

// Define the 8x8 Spatial Map structure
typedef struct {
    uint64_t tile_hashes[64];
} AegisMap;

void handle_errors() {
    ERR_print_errors_fp(stderr);
    exit(1);
}

// Feature: Anti-AI Spectral Shield
void apply_spectral_shield(unsigned char *p, int w, int h, int c) {
    for (int y = 0; y < h; y++) {
        for (int x = 0; x < w; x++) {
            float pattern = sinf(x * 0.5f) * cosf(y * 0.5f);
            for (int k = 0; k < c; k++) {
                int i = (y * w + x) * c + k;
                float val = (float)p[i] + (pattern * 7.0f);
                p[i] = (unsigned char)fminf(255.0f, fmaxf(0.0f, val));
            }
        }
    }
}

// Compute hash for a specific grid sector (tx, ty)
uint64_t compute_tile_hash(unsigned char *pixels, int w, int h, int c, int tx, int ty) {
    uint64_t hash = 0;
    double total = 0;
    unsigned char small[64];
    int tw = w / 8; // tile width
    int th = h / 8; // tile height

    for (int y = 0; y < 8; y++) {
        for (int x = 0; x < 8; x++) {
            int px = (tx * tw) + (x * tw / 8);
            int py = (ty * th) + (y * th / 8);
            int idx = (py * w + px) * c;
            small[y * 8 + x] = (pixels[idx] + pixels[idx+1] + pixels[idx+2]) / 3;
            total += small[y * 8 + x];
        }
    }
    double avg = total / 64.0;
    for (int i = 0; i < 64; i++) if (small[i] >= avg) hash |= (1ULL << i);
    return hash;
}

int main() {
    printf("--- AEGIS CAMERA: SPATIAL MODE ---\n");
    int w, h, c;
    unsigned char *pixels = stbi_load("input.jpg", &w, &h, &c, 0);
    if (!pixels) { printf("Error: input.jpg not found\n"); return 1; }

    // 1. Poison the image
    apply_spectral_shield(pixels, w, h, c);
    stbi_write_jpg("protected.jpg", w, h, c, pixels, 90);
    stbi_image_free(pixels);

    // 2. Reload to generate the Map (Post-Compression)
    unsigned char *saved = stbi_load("protected.jpg", &w, &h, &c, 0);
    AegisMap map;
    printf("Mapping 64 spatial sectors...\n");
    for (int ty = 0; ty < 8; ty++) {
        for (int tx = 0; tx < 8; tx++) {
            map.tile_hashes[ty * 8 + tx] = compute_tile_hash(saved, w, h, c, tx, ty);
        }
    }

    // 3. Save the Map file
    FILE *m_file = fopen("aegis.map", "wb");
    fwrite(&map, sizeof(AegisMap), 1, m_file);
    fclose(m_file);

    // 4. Sign the Map (This locks the evidence grid)
    FILE *kf = fopen("private.pem", "r");
    if (!kf) { printf("Error: private.pem missing\n"); return 1; }
    EVP_PKEY *pk = PEM_read_PrivateKey(kf, NULL, NULL, NULL);
    fclose(kf);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    size_t slen;
    unsigned char *sig;
    EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pk);
    EVP_DigestSignUpdate(ctx, &map, sizeof(AegisMap)); // Signing the metadata map
    EVP_DigestSignFinal(ctx, NULL, &slen);
    sig = malloc(slen);
    EVP_DigestSignFinal(ctx, sig, &slen);

    FILE *sf = fopen("signature.sig", "wb");
    fwrite(sig, 1, slen, sf);
    fclose(sf);

    printf("SUCCESS: protected.jpg, signature.sig, aegis.map generated.\n");
    
    stbi_image_free(saved);
    EVP_PKEY_free(pk);
    EVP_MD_CTX_free(ctx);
    free(sig);
    return 0;
}