#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

// This structure holds our 64 localized aHashes
typedef struct { uint64_t tile_hashes[64]; } AegisMap;

// Mathematical Brain: The Perceptual Hash (aHash) for a single tile
uint64_t compute_tile_hash(unsigned char *pixels, int w, int h, int c, int tx, int ty) {
    uint64_t hash = 0; double total = 0; unsigned char small[64];
    int tw = w/8; int th = h/8; // Calculate tile width/height
    
    for (int y = 0; y < 8; y++) {
        for (int x = 0; x < 8; x++) {
            // Pick a pixel within this 8x8 tile
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
    int w, h, c;
    unsigned char *pixels = stbi_load("protected.jpg", &w, &h, &c, 0);
    if (!pixels) { printf("Error: 'protected.jpg' missing\n"); return 1; }

    // 1. Load the 64 saved ahashes
    AegisMap saved_map;
    FILE *mf = fopen("aegis.map", "rb");
    if (!mf) { printf("Error: 'aegis.map' missing\n"); return 1; }
    fread(&saved_map, sizeof(AegisMap), 1, mf);
    fclose(mf);

    // 2. Load the signature of the map
    FILE *sf = fopen("signature.sig", "rb");
    fseek(sf, 0, SEEK_END); size_t slen = ftell(sf); fseek(sf, 0, SEEK_SET);
    unsigned char *sig = malloc(slen); fread(sig, 1, slen, sf); fclose(sf);

    // 3. Load Public Key
    FILE *pkf = fopen("public.pem", "r");
    EVP_PKEY *pk = PEM_read_PUBKEY(pkf, NULL, NULL, NULL); fclose(pkf);

    // 4. Identity Check: Verify the signature of the map manifest
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pk);
    EVP_DigestVerifyUpdate(ctx, &saved_map, sizeof(AegisMap));
    
    if (EVP_DigestVerifyFinal(ctx, sig, slen) != 1) {
        printf("\n[!] CRITICAL: IDENTITY THEFT DETECTED. The Map signature is invalid.\n");
        return 1;
    }

    // 5. Grid Scan: Compare local hashes bit by bit
    printf("\n--- AEGIS SPATIAL INTEGRITY SCAN ---\n\n");
    int error_count = 0;
    for (int ty = 0; ty < 8; ty++) {
        for (int tx = 0; tx < 8; tx++) {
            uint64_t current_h = compute_tile_hash(pixels, w, h, c, tx, ty);
            uint64_t saved_h = saved_map.tile_hashes[ty * 8 + tx];
            
            // Hamming Distance Calculation
            uint64_t x = saved_h ^ current_h;
            int diff = 0;
            while (x > 0) { if (x & 1) diff++; x >>= 1; }

            // Threshold: If more than 3 bits differ, mark as an AI change
            if (diff > 3) {
                printf("[ X ] "); // Prints X only where pixels don't match
                error_count++;
            } else {
                printf("[OK ] "); // Prints OK for the verified areas
            }
        }
        printf("\n");
    }

    printf("\nSUMMARY:\n");
    if (error_count == 0) {
        printf("VERDICT: FULLY VERIFIED. No modifications detected.\n");
    } else {
        printf("VERDICT: TAMPERED. Detected changes in %d spatial blocks.\n", error_count);
    }
    printf("------------------------------------\n\n");

    return 0;
}