#!/usr/bin/env bash
set -euo pipefail
pio run -t clean
pio run -t upload
pio device monitor
