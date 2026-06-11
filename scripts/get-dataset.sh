#!/usr/bin/env bash
# get-dataset.sh - download "The Case of the Stolen Szechuan Sauce" (DFIRmadness Case 001)
#
# Source: https://dfirmadness.com/the-stolen-szechuan-sauce/
# URLs + MD5s taken from the case page and verified live (HTTP 200) on 2026-06-11.
# Total download: ~13.5 GB zipped (DC + desktop E01 images, memory captures,
# pagefiles, autoruns, protected files, pcap). Expands to ~25-30 GB.
#
# Usage (on the SIFT VM):
#   ./scripts/get-dataset.sh [target_dir]      # default target: /cases/szechuan/
#
# Idempotent and resume-safe: re-running skips files that already pass MD5,
# resumes partial downloads (curl -C - / wget -c), and re-verifies everything.
# After download it computes SHA-256 for every archive into SHA256SUMS.txt -
# checklist item 2 records these in docs/dataset.md.

set -u -o pipefail

TARGET_DIR="${1:-/cases/szechuan}"
BASE_URL="https://dfirmadness.com/case001"

# filename|url-path (url-encoded where needed)|published MD5 (from the case page)
# Note: the case page's hash table lists "DESKTOP-SDN1RPT-autrunsc.zip" (sic);
# the actual download is DESKTOP-SDN1RPT-autorunsc.zip - same file, page typo.
FILES=(
  "case001-pcap.zip|case001-pcap.zip|422046B753CF8A4DF49D2C4CE892DB16"
  "DC01-E01.zip|DC01-E01.zip|E57FC636E833C5F1AB58DFACE873BBDE"
  "DC01-memory.zip|DC01-memory.zip|64A4E2CB47138084A5C2878066B2D7B1"
  "DC01-pagefile.zip|DC01-pagefile.zip|964EEAF0009D08CC101DE4A83A4E5D23"
  "DC01-autorunsc.zip|DC01-autorunsc.zip|964F2D710687D170C77C94947DA29E66"
  "DC01-ProtectedFiles.zip|DC01-ProtectedFiles.zip|AD29830A583EFE49C8C1C35FAFFD264F"
  "DESKTOP-E01.zip|DESKTOP-E01.zip|71C5C3509331F472ABCDF81EB6EFFF07"
  "DESKTOP-SDN1RPT-memory.zip|DESKTOP-SDN1RPT-memory.zip|CF31E2635C77811AAA1BB04A92A721E2"
  "Desktop-SDN1RPT-pagefile.zip|Desktop-SDN1RPT-pagefile.zip|45C096F2688A0B5DE0346FB72391B245"
  "DESKTOP-SDN1RPT-autorunsc.zip|DESKTOP-SDN1RPT-autorunsc.zip|3627DCAFA54E1365489A4EC0CC3D6A1C"
  "DESKTOP-SDN1RPT-Protected Files.zip|DESKTOP-SDN1RPT-Protected%20Files.zip|3E1A358D50003A9351AC2160AE6F0495"
)

log()  { printf '[get-dataset] %s\n' "$*"; }
fail() { printf '[get-dataset] ERROR: %s\n' "$*" >&2; }

md5_of() {
  md5sum "$1" | awk '{print $1}' | tr 'a-f' 'A-F'
}

verify_md5() {
  local file="$1" expected="$2" actual
  actual="$(md5_of "$file")"
  [ "$actual" = "$(printf '%s' "$expected" | tr 'a-f' 'A-F')" ]
}

download() {
  # Resume-capable download: curl preferred, wget fallback.
  local url="$1" dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fL --retry 5 --retry-delay 10 -C - --progress-bar -o "$dest" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -c --tries=5 -O "$dest" "$url"
  else
    fail "need curl or wget"; return 127
  fi
}

mkdir -p "$TARGET_DIR" || { fail "cannot create $TARGET_DIR (try sudo mkdir -p $TARGET_DIR && sudo chown \$USER $TARGET_DIR)"; exit 1; }
cd "$TARGET_DIR"

log "target: $TARGET_DIR"
log "source: $BASE_URL (DFIRmadness Case 001)"
log "total ~13.5 GB zipped - this runs for a while; safe to re-run/resume."

failures=0
for entry in "${FILES[@]}"; do
  IFS='|' read -r name urlpath md5 <<< "$entry"
  url="$BASE_URL/$urlpath"

  if [ -f "$name" ] && verify_md5 "$name" "$md5"; then
    log "OK (cached)   $name"
    continue
  fi

  log "downloading   $name"
  if ! download "$url" "$name"; then
    fail "download failed: $url"
    failures=$((failures + 1))
    continue
  fi

  if verify_md5 "$name" "$md5"; then
    log "OK (verified) $name  MD5=$md5"
  else
    fail "MD5 MISMATCH for $name (expected $md5, got $(md5_of "$name")) - deleting; re-run to retry"
    rm -f -- "$name"
    failures=$((failures + 1))
  fi
done

if [ "$failures" -gt 0 ]; then
  fail "$failures file(s) failed - re-run this script to resume/retry"
  exit 1
fi

log "all archives present and MD5-verified."

log "computing SHA-256 for the record (item 2 copies these into docs/dataset.md)..."
sha256sum -- *.zip | tee SHA256SUMS.txt

log "extracting archives (skipped if already extracted)..."
for entry in "${FILES[@]}"; do
  IFS='|' read -r name _ _ <<< "$entry"
  marker=".extracted-$(printf '%s' "$name" | tr ' ' '_')"
  if [ -f "$marker" ]; then
    log "OK (extracted) $name"
    continue
  fi
  if command -v unzip >/dev/null 2>&1; then
    if unzip -o -q -- "$name" -d .; then
      touch "$marker"
      log "extracted      $name"
    else
      fail "unzip failed for $name (archive kept; investigate manually)"
      failures=$((failures + 1))
    fi
  else
    fail "unzip not found - install it (sudo apt-get install unzip) and re-run"
    exit 1
  fi
done

if [ "$failures" -gt 0 ]; then
  exit 1
fi

log "done. evidence ready under $TARGET_DIR"
log "next: verdict investigate $TARGET_DIR"
