#include "../key_manager/include/key_manager.h"
#include "../video/video_verify.c"
#include <stdio.h>


int main(int argc, char **argv) {
  if (argc != 2) {
    printf("Usage: %s <video.mp4>\n", argv[0]);
    return 1;
  }

  km_config_t cfg = {.backend = KM_SOFTWARE,
                     .key_path = "keys/hemlock_private.pem"};

  if (km_init(&cfg) != 0) {
    printf("Key init failed\n");
    return 1;
  }

  return verify_video(argv[1]);
}