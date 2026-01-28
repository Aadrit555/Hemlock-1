#!/bin/bash
ffmpeg -loglevel error -i "$1" -vf scale=224:224 -f rawvideo -pix_fmt rgb24 frames/out.raw