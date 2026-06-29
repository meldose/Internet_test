#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ps_script_win="$(wslpath -w "${script_dir}/windows_wifi_monitor.ps1")"

exec powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$ps_script_win" "$@"
