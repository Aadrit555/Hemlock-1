#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
// Capture $\rightarrow$ Poison $\rightarrow$ Sign
#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image_write.h"

void handle_errors() {
    ERR_print_errors_fp(stderr);
    exit(1);
}

int main() {
    int width, height, channels;
    unsigned char *pixels = stbi_load("input.jpg", &width, &height, &channels, 0);
    if (!pixels) {
        printf("Error: Could not load input.jpg\n");
        return 1;
    }

    printf("Poisoning image: %dx%d (%d channels)...\n", width, height, channels);

    // Step A: Poison (Deterministic noise)
    srand(42); // Seed for reproducible noise
    for (int i = 0; i < width * height * channels; i++) {
        int noise = rand() % 256;
        double poisoned = (double)pixels[i] + (noise * 0.05);
        pixels[i] = (unsigned char)fmin(255.0, poisoned);
    }

    // Basically It iterates through every single byte of color data (Red, Green, Blue) and adds a tiny amount of static noise.

    // Step D: Save the poisoned image
    stbi_write_jpg("protected.jpg", width, height, channels, pixels, 90);
    stbi_image_free(pixels);

    // The name of the file to create on your hard drive.

    

    // CRITICAL: Reload the image to get the "compressed" pixels for signing
    // This ensures the Verifier sees the exact same pixel data.
    int w2, h2, c2;
    unsigned char *saved_pixels = stbi_load("protected.jpg", &w2, &h2, &c2, 0);
    size_t pixel_size = w2 * h2 * c2;

    // Step B & C: Sign the hash of the pixels
    FILE *priv_key_file = fopen("private.pem", "r");
    if (!priv_key_file) { perror("private.pem"); return 1; }
    EVP_PKEY *priv_key = PEM_read_PrivateKey(priv_key_file, NULL, NULL, NULL);
    fclose(priv_key_file);

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    size_t sig_len;
    unsigned char *sig = NULL;

    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, priv_key) <= 0) handle_errors();
    if (EVP_DigestSignUpdate(md_ctx, saved_pixels, pixel_size) <= 0) handle_errors();
    
    // Determine buffer size for signature
    if (EVP_DigestSignFinal(md_ctx, NULL, &sig_len) <= 0) handle_errors();
    sig = malloc(sig_len);
    if (EVP_DigestSignFinal(md_ctx, sig, &sig_len) <= 0) handle_errors();

    // Step E: Save signature
    FILE *sig_file = fopen("signature.sig", "wb");
    fwrite(sig, 1, sig_len, sig_file);
    fclose(sig_file);

    printf("Success: protected.jpg and signature.sig generated.\n");

    stbi_image_free(saved_pixels);
    EVP_PKEY_free(priv_key);
    EVP_MD_CTX_free(md_ctx);
    free(sig);

    return 0;
}