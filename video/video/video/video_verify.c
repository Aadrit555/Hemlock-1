#include "../common/hash_utils.h"
#include "../key_manager/include/key_manager.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WIDTH 224
#define HEIGHT 224
#define CHANNELS 3
#define FRAME_SIZE (WIDTH * HEIGHT * CHANNELS)

int verify_video(const char *video_path) {
  system("rm -rf frames && mkdir frames");

  char cmd[512];
  snprintf(cmd, sizeof(cmd),
           "ffmpeg -loglevel error -i %s -vf scale=%d:%d "
           "-f rawvideo -pix_fmt rgb24 frames/out.raw",
           video_path, WIDTH, HEIGHT);

  if (system(cmd) != 0) {
    printf("FFmpeg failed\n");
    return -1;
  }

  FILE *f = fopen("frames/out.raw", "rb");
  FILE *chain = fopen("provenance/video_chain.bin", "rb");

  if (!f || !chain) {
    printf("Missing provenance files\n");
    return -1;
  }

  uint8_t frame[FRAME_SIZE];
  uint8_t prev_hash[32] = {0};
  uint8_t expected[32], computed[32];

  int frame_id = 0;

  while (fread(frame, 1, FRAME_SIZE, f) == FRAME_SIZE) {
    if (fread(expected, 1, 32, chain) != 32) {
      printf("✘ Chain length mismatch\n");
      return -1;
    }

    sha256_chain(frame, FRAME_SIZE, prev_hash, computed);

    if (memcmp(expected, computed, 32) != 0) {
      printf("✘ Tampering detected at frame %d\n", frame_id);
      return -1;
    }

    memcpy(prev_hash, computed, 32);
    frame_id++;
  }

  fclose(f);
  fclose(chain);

  // Verify final signature
  FILE *sf = fopen("provenance/video_sig.bin", "rb");
  if (!sf)
    return -1;

  uint8_t sig[512];
  size_t sig_len = fread(sig, 1, sizeof(sig), sf);
  fclose(sf);

  if (km_verify(prev_hash, 32, sig, sig_len) != 0) {
    printf("✘ Final signature invalid\n");
    return -1;
  }

  printf("✔ Video verified successfully\n");
  return 0;
}