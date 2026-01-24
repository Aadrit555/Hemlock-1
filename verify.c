#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

int main() {
    int width, height, channels;
    unsigned char *pixels = stbi_load("protected.jpg", &width, &height, &channels, 0);
    if (!pixels) {
        printf("Error: Could not load protected.jpg\n");
        return 1;
    }
    size_t pixel_size = width * height * channels;

    // Load Signature
    FILE *sig_file = fopen("signature.sig", "rb");
    if (!sig_file) { printf("Missing signature.sig\n"); return 1; }
    fseek(sig_file, 0, SEEK_END);
    size_t sig_len = ftell(sig_file);
    fseek(sig_file, 0, SEEK_SET);
    unsigned char *sig = malloc(sig_len);
    fread(sig, 1, sig_len, sig_file);
    fclose(sig_file);

    // Load Public Key
    FILE *pub_key_file = fopen("public.pem", "r");
    EVP_PKEY *pub_key = PEM_read_PUBKEY(pub_key_file, NULL, NULL, NULL);
    fclose(pub_key_file);

    // Verify
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pub_key) <= 0) return 1;
    if (EVP_DigestVerifyUpdate(md_ctx, pixels, pixel_size) <= 0) return 1;

    int result = EVP_DigestVerifyFinal(md_ctx, sig, sig_len);

    if (result == 1) {
        printf("RESULT: VERIFIED\n");
    } else {
        printf("RESULT: TAMPERED\n");
    }

    stbi_image_free(pixels);
    free(sig);
    EVP_PKEY_free(pub_key);
    EVP_MD_CTX_free(md_ctx);

    return 0;
    // change
}