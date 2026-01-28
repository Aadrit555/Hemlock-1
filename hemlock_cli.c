#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void usage() {
    printf("Usage:\n");
    printf("  hemlock sign image <file>\n");
    printf("  hemlock verify image <file>\n");
    printf("  hemlock sign video <file>\n");
    printf("  hemlock verify video <file>\n");
}

int main(int argc, char **argv) {
    if (argc != 4) {
        usage();
        return 1;
    }

    const char *action = argv[1];
    const char *type   = argv[2];
    const char *file   = argv[3];

    char cmd[512];

    // IMAGE PIPELINE (C)
    if (strcmp(type, "image") == 0) {
        if (strcmp(action, "sign") == 0) {
            snprintf(cmd, sizeof(cmd), "image_sign.exe \"%s\"", file);
        } else if (strcmp(action, "verify") == 0) {
            snprintf(cmd, sizeof(cmd), "image_verify.exe \"%s\"", file);
        } else {
            usage();
            return 1;
        }
    }

    // VIDEO PIPELINE (Python)
    else if (strcmp(type, "video") == 0) {
        if (strcmp(action, "sign") == 0) {
            snprintf(cmd, sizeof(cmd),
                     "python video_py\\video_sign.py \"%s\"", file);
        } else if (strcmp(action, "verify") == 0) {
            snprintf(cmd, sizeof(cmd),
                     "python video_py\\video_verify.py \"%s\"", file);
        } else {
            usage();
            return 1;
        }
    }

    else {
        usage();
        return 1;
    }

    return system(cmd);
}
