#include "video_hash.h"
#include "../common/hash_utils.h"
#include "../key_manager/include/key_manager.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WIDTH 224
#define HEIGHT 224
#define CHANNELS 3
#define FRAME_SIZE (WIDTH * HEIGHT * CHANNELS)

int sign_video(const char *video_path) {
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
  if (!f)
    return -1;

  FILE *chain = fopen("provenance/video_chain.bin", "wb");
  if (!chain)
    return -1;

  uint8_t frame[FRAME_SIZE];
  uint8_t prev_hash[32] = {0};
  uint8_t curr_hash[32];

  while (fread(frame, 1, FRAME_SIZE, f) == FRAME_SIZE) {
    sha256_chain(frame, FRAME_SIZE, prev_hash, curr_hash);
    fwrite(curr_hash, 1, 32, chain);
    memcpy(prev_hash, curr_hash, 32);
  }

  fclose(f);
  fclose(chain);

  // Sign final hash
  uint8_t *sig = NULL;
  size_t sig_len = 0;

  if (km_sign(curr_hash, 32, &sig, &sig_len) != 0) {
    printf("Signing failed\n");
    return -1;
  }

  FILE *sf = fopen("provenance/video_sig.bin", "wb");
  fwrite(sig, 1, sig_len, sf);
  fclose(sf);

  free(sig);
  printf("✔ Video signed successfully\n");
  return 0;
}