#!/usr/bin/env bash
set -euo pipefail

# appi — User-space AppImage layout + desktop integration (no daemon, no root for normal install/run; some fixes require sudo)
# Default root: ~/Apps (override via --root or APPI_ROOT)
#
# Layout:
#   <root>/<app_id>/versions/<file>.AppImage
#   <root>/<app_id>/current -> versions/<file>.AppImage
#   <root>/<app_id>/icons/<app_id>.png        (best-effort)
#   <root>/<app_id>/desktop/<app_id>.desktop  (generated copy)
# Desktop install:
#   ~/.local/share/applications/<app_id>.desktop
# Optional CLI link:
#   ~/.local/bin/<app_id> -> <root>/<app_id>/current

PROG="appi"

ROOT_DEFAULT="${APPI_ROOT:-$HOME/Apps}"
ROOT="$ROOT_DEFAULT"

DRY_RUN=0
QUIET=0
VERBOSE=0

# ---------- logging / utils ----------

die() { echo "Error: $*" >&2; exit 1; }

log() { (( QUIET )) || echo "$*"; }

vlog() { (( VERBOSE )) && (( !QUIET )) && echo "$*"; true; }

run_cmd() {
  # shellcheck disable=SC2145
  if (( DRY_RUN )); then
    log "[dry-run] $*"
    return 0
  fi
  "$@"
}

ensure_dir() { run_cmd mkdir -p "$1"; }

have_cmd() { command -v "$1" >/dev/null 2>&1; }

compute_checksum() {
  local file="$1"
  local checksum=""
  if have_cmd sha256sum; then
    checksum="$(sha256sum <"$file" | cut -d' ' -f1 || echo "")"
    [[ -n "$checksum" ]] || die "Failed to compute checksum with sha256sum"
  elif have_cmd shasum; then
    checksum="$(shasum -a 256 <"$file" | cut -d' ' -f1 || echo "")"
    [[ -n "$checksum" ]] || die "Failed to compute checksum with shasum"
  elif have_cmd openssl; then
    checksum="$(openssl dgst -sha256 <"$file" | cut -d' ' -f2 || echo "")"
    [[ -n "$checksum" ]] || die "Failed to compute checksum with openssl"
  else
    die "No checksum tool found (need sha256sum, shasum, or openssl)"
  fi
  [[ -n "$checksum" ]] || die "Checksum computation returned empty result"
  echo "$checksum"
}

extracted_marker_path() {
  local app_dir="$1"
  echo "$app_dir/meta/extracted.marker"
}

read_extracted_marker_checksum() {
  local app_dir="$1"
  local marker
  marker="$(extracted_marker_path "$app_dir")"
  [[ -f "$marker" ]] || return 1
  awk 'NF{print $1; exit}' "$marker" 2>/dev/null
}

write_extracted_marker() {
  local app_dir="$1"
  local checksum="$2"
  local filename="${3:-}"
  local marker
  marker="$(extracted_marker_path "$app_dir")"

  if (( DRY_RUN )); then
    log "[dry-run] write extracted marker: $checksum  $filename"
    return 0
  fi

  ensure_dir "$(dirname "$marker")"
  printf "%s  %s\n" "$checksum" "$filename" >"$marker"
}

clear_extracted_marker() {
  local app_dir="$1"
  local marker
  marker="$(extracted_marker_path "$app_dir")"
  if (( DRY_RUN )); then
    log "[dry-run] remove extracted marker: $marker"
    return 0
  fi
  rm -f "$marker"
}

extracted_marker_matches() {
  local app_dir="$1"
  local checksum="$2"
  local existing
  existing="$(read_extracted_marker_checksum "$app_dir" || true)"
  [[ -n "$existing" && "$existing" == "$checksum" ]]
}

chrome_sandbox_marker_path() {
  local app_dir="$1"
  echo "$app_dir/meta/chrome-sandbox.marker"
}

has_chrome_sandbox_fix() {
  local app_dir="$1"
  local marker
  marker="$(chrome_sandbox_marker_path "$app_dir")"
  [[ -f "$marker" ]]
}

write_chrome_sandbox_marker() {
  local app_dir="$1"
  local marker
  marker="$(chrome_sandbox_marker_path "$app_dir")"

  if (( DRY_RUN )); then
    log "[dry-run] write chrome-sandbox marker: $marker"
    return 0
  fi

  ensure_dir "$(dirname "$marker")"
  touch "$marker"
}

clear_chrome_sandbox_marker() {
  local app_dir="$1"
  local marker
  marker="$(chrome_sandbox_marker_path "$app_dir")"
  if (( DRY_RUN )); then
    log "[dry-run] remove chrome-sandbox marker: $marker"
    return 0
  fi
  rm -f "$marker"
}

apply_chrome_sandbox_fix() {
  local app_dir="$1"
  local squashfs_root="$2"
  local skip_prompt="${3:-0}"  # Optional: skip prompt for auto-reapplication

  # Find chrome-sandbox
  local sandbox_path
  sandbox_path="$(find "$squashfs_root" -name "chrome-sandbox" -type f 2>/dev/null | head -n1)"

  if [[ -z "$sandbox_path" ]]; then
    if (( skip_prompt )); then
      log "Warning: chrome-sandbox not found in extracted AppImage (fix was previously applied but binary missing)"
      return 1
    else
      die "chrome-sandbox not found in extracted AppImage"
    fi
  fi

  log "Found chrome-sandbox at: $sandbox_path"

  # Set SUID bit (requires sudo)
  if (( DRY_RUN )); then
    log "[dry-run] sudo chown root:root $sandbox_path"
    log "[dry-run] sudo chmod 4755 $sandbox_path"
  else
    if ! sudo chown root:root "$sandbox_path" 2>/dev/null; then
      die "Failed to set ownership (requires sudo)"
    fi
    if ! sudo chmod 4755 "$sandbox_path" 2>/dev/null; then
      die "Failed to set SUID bit (requires sudo)"
    fi
    log "Set SUID bit on chrome-sandbox"
  fi

  # Write marker to track that fix was applied
  write_chrome_sandbox_marker "$app_dir"
  return 0
}

extract_appimage() {
  local app_dir="$1"
  local appimage_path="$2"
  local checksum="${3:-}"
  local filename="${4:-}"

  local extracted_dir="$app_dir/extracted"
  local squashfs_root="$extracted_dir/squashfs-root"

  ensure_dir "$extracted_dir"
  if [[ -d "$squashfs_root" ]]; then
    log "Removing existing extraction for clean re-extract..."
    run_cmd rm -rf "$squashfs_root"
  fi

  log "Extracting AppImage..."
  if (( DRY_RUN )); then
    log "[dry-run] extract $appimage_path to $extracted_dir"
  else
    ( cd "$extracted_dir" && "$appimage_path" --appimage-extract >/dev/null 2>&1 ) || \
      die "Failed to extract AppImage (does it support --appimage-extract?)"
  fi

  [[ -d "$squashfs_root" ]] || die "Extraction did not create squashfs-root"

  if [[ -n "$checksum" ]]; then
    write_extracted_marker "$app_dir" "$checksum" "$filename"
  fi
}

get_checksum_file() {
  local app_dir="$1"
  echo "$app_dir/meta/checksums.txt"
}

store_checksum() {
  local app_dir="$1"
  local filename="$2"
  local checksum="$3"
  local checksum_file
  checksum_file="$(get_checksum_file "$app_dir")"
  
  if (( DRY_RUN )); then
    log "[dry-run] store checksum: $checksum  $filename"
    return 0
  fi
  
  # Remove existing entry for this filename if any, then append new one
  if [[ -f "$checksum_file" ]]; then
    grep -v "^[0-9a-f]\{64\}  $filename\$" "$checksum_file" >"$checksum_file.tmp" 2>/dev/null || true
    mv -f "$checksum_file.tmp" "$checksum_file" 2>/dev/null || true
  fi
  
  # Append new entry: checksum (64 hex chars) + 2 spaces + filename
  printf "%s  %s\n" "$checksum" "$filename" >>"$checksum_file"
}

find_existing_by_checksum() {
  local app_dir="$1"
  local checksum="$2"
  local checksum_file
  checksum_file="$(get_checksum_file "$app_dir")"
  
  if [[ ! -f "$checksum_file" ]]; then
    return 1
  fi
  
  # Look for matching checksum in stored entries
  local match
  match="$(grep "^$checksum  " "$checksum_file" 2>/dev/null | head -n1 || true)"
  if [[ -z "$match" ]]; then
    return 1
  fi
  
  # Extract filename (everything after checksum + 2 spaces)
  local filename
  filename="${match#*  }"
  
  # Verify the file still exists
  local full_path="$app_dir/versions/$filename"
  if [[ -f "$full_path" ]]; then
    echo "$filename"
    return 0
  else
    # File was deleted but checksum entry remains, clean it up
    if (( !DRY_RUN )); then
      grep -v "^$checksum  " "$checksum_file" >"$checksum_file.tmp" 2>/dev/null || true
      mv -f "$checksum_file.tmp" "$checksum_file" 2>/dev/null || true
    fi
    return 1
  fi
}

remove_checksum_entry() {
  local app_dir="$1"
  local filename="$2"
  local checksum_file
  checksum_file="$(get_checksum_file "$app_dir")"
  
  if [[ ! -f "$checksum_file" ]]; then
    return 0
  fi
  
  if (( DRY_RUN )); then
    log "[dry-run] remove checksum entry for: $filename"
    return 0
  fi
  
  grep -v "^[0-9a-f]\{64\}  $filename\$" "$checksum_file" >"$checksum_file.tmp" 2>/dev/null || true
  mv -f "$checksum_file.tmp" "$checksum_file" 2>/dev/null || true
}

pretty_name() {
  # app_id -> Title Case-ish
  local s="$1"
  s="${s//_/ }"
  s="${s//-/ }"
  # capitalize each word's first char (best-effort)
  awk '{
    for (i=1;i<=NF;i++){
      $i=toupper(substr($i,1,1)) substr($i,2)
    }
    print
  }' <<<"$s"
}

normalize_app_id() {
  local id="$1"
  id="${id,,}" # lowercase
  # allow a-z 0-9 and dashes only
  if [[ ! "$id" =~ ^[a-z0-9]+([a-z0-9-]*[a-z0-9])?$ ]]; then
    die "Invalid app_id '$id' (allowed: lowercase letters, digits, dashes; must start/end with alnum)"
  fi
  echo "$id"
}

infer_app_id_from_filename() {
  local p="$1"
  local b
  b="$(basename "$p")"
  b="${b%.AppImage}"
  b="${b%.appimage}"
  b="${b,,}"
  # replace non-alnum with dash, collapse repeats, trim
  b="$(sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//; s/-+/-/g' <<<"$b")"
  [[ -n "$b" ]] || die "Could not infer app_id from filename"
  echo "$b"
}

unique_target_path() {
  local dir="$1"
  local base="$2"
  local out="$dir/$base"
  if [[ ! -e "$out" ]]; then
    echo "$out"
    return 0
  fi
  local ts
  ts="$(date +%Y%m%d%H%M%S)"
  echo "$dir/${base%.AppImage}-$ts.AppImage"
}

desktop_paths() {
  local id="$1"
  local app_dir="$ROOT/$id"
  local local_share="$HOME/.local/share/applications"
  echo "$app_dir/desktop/$id.desktop|$local_share/$id.desktop"
}

write_desktop_file() {
  local id="$1"
  local app_dir="$ROOT/$id"
  local pretty
  pretty="$(pretty_name "$id")"

  local icon_path="$app_dir/icons/$id.png"
  local exec_path="$app_dir/run"

  IFS="|" read -r app_copy desktop_install < <(desktop_paths "$id")

  ensure_dir "$(dirname "$app_copy")"
  ensure_dir "$(dirname "$desktop_install")"

  # NOTE: If ROOT contains spaces, some desktop environments may not parse Exec/Icon cleanly.
  # We wrap Exec/TryExec in quotes to improve compatibility.
  local content
  content=$(
    cat <<EOF
[Desktop Entry]
Type=Application
Name=$pretty
Comment=AppImage
Exec="$exec_path" %U
TryExec="$exec_path"
Terminal=false
Categories=Utility;
StartupNotify=true
EOF
  )

  if [[ -f "$icon_path" ]]; then
    content+=$'\n'"Icon=$icon_path"
  fi

  if (( DRY_RUN )); then
    log "[dry-run] write $app_copy"
    log "[dry-run] write $desktop_install"
  else
    printf "%s\n" "$content" >"$app_copy"
    printf "%s\n" "$content" >"$desktop_install"
  fi

  vlog "Desktop entry written:"
  vlog "  - $app_copy"
  vlog "  - $desktop_install"
}

maybe_extract_icon() {
  local id="$1"
  local app_dir="$ROOT/$id"
  local exec_path="$app_dir/current"
  local out="$app_dir/icons/$id.png"

  ensure_dir "$app_dir/icons"

  # best-effort: requires AppImage to support --appimage-extract
  local tmp
  tmp="$(mktemp -d)"
  if (( DRY_RUN )); then
    log "[dry-run] icon extract (best-effort) for $id"
    run_cmd rm -rf "$tmp"
    return 0
  fi

  # Extraction happens in current working directory -> squashfs-root
  # Run in tmp directory to avoid polluting current directory
  ( cd "$tmp" && "$exec_path" --appimage-extract >/dev/null 2>&1 ) || {
    vlog "Icon extract skipped: --appimage-extract not supported or extraction failed for $id"
    run_cmd rm -rf "$tmp"
    return 0
  }

  local root="$tmp/squashfs-root"
  [[ -d "$root" ]] || { run_cmd rm -rf "$tmp"; return 0; }

  local best=""
  local best_score=-1

  # Candidates: hicolor icons and pixmaps
  while IFS= read -r -d '' f; do
    local score=0
    if [[ "$f" =~ /hicolor/([0-9]+)x([0-9]+)/apps/ ]]; then
      score=$(( BASH_REMATCH[1] * BASH_REMATCH[2] ))
    fi
    if (( score > best_score )); then
      best_score="$score"
      best="$f"
    fi
  done < <(find "$root" -type f \( \
      -path "*/usr/share/icons/hicolor/*/apps/*.png" -o \
      -path "*/usr/share/pixmaps/*.png" \
    \) -print0 2>/dev/null || true)

  # Fallback: .DirIcon
  if [[ -z "$best" && -e "$root/.DirIcon" ]]; then
    best="$root/.DirIcon"
  fi

  if [[ -n "$best" && -f "$best" ]]; then
    run_cmd cp -f "$best" "$out" || true
    vlog "Icon extracted -> $out"
  else
    vlog "No icon candidate found for $id"
  fi

  run_cmd rm -rf "$tmp"
}

maybe_link_bin() {
  local id="$1"
  local mode="$2" # on|off|auto
  local target="$ROOT/$id/run"
  local bin_dir="$HOME/.local/bin"
  local link="$bin_dir/$id"

  if [[ "$mode" == "off" ]]; then
    return 0
  fi
  if [[ "$mode" == "auto" && ! -d "$bin_dir" ]]; then
    vlog "Bin link skipped (auto): $bin_dir does not exist"
    return 0
  fi

  ensure_dir "$bin_dir"
  run_cmd ln -sfn "$target" "$link"
  vlog "Bin link -> $link"
}

unlink_bin() {
  local id="$1"
  local link="$HOME/.local/bin/$id"
  if [[ -L "$link" || -e "$link" ]]; then
    run_cmd rm -f "$link"
    vlog "Removed bin link: $link"
  fi
}

remove_desktop_install() {
  local id="$1"
  local path="$HOME/.local/share/applications/$id.desktop"
  if [[ -f "$path" ]]; then
    run_cmd rm -f "$path"
    vlog "Removed desktop entry: $path"
  fi
}

ensure_run_wrapper() {
  local id="$1"
  local app_dir="$ROOT/$id"
  local wrapper="$app_dir/run"

  if (( DRY_RUN )); then
    log "[dry-run] create wrapper script: $wrapper"
    return 0
  fi

  cat >"$wrapper" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# Resolve symlinks to get the actual script location
SCRIPT="$0"
while [[ -L "$SCRIPT" ]]; do
  SCRIPT="$(readlink "$SCRIPT")"
  [[ "$SCRIPT" != /* ]] && SCRIPT="$(dirname "$0")/$SCRIPT"
done
APPDIR="$(cd "$(dirname "$SCRIPT")" && pwd)"
if [[ -x "$APPDIR/extracted/squashfs-root/AppRun" ]]; then
  echo "Using extracted AppRun at $APPDIR/extracted/squashfs-root/AppRun" >&2
  exec "$APPDIR/extracted/squashfs-root/AppRun" "$@"
fi
# Check for FUSE before running AppImage
if ! ldconfig -p 2>/dev/null | grep -q libfuse.so.2; then
  # Fallback check
  found=0
  for path in /usr/lib/x86_64-linux-gnu/libfuse.so.2 /usr/lib/libfuse.so.2 /lib/x86_64-linux-gnu/libfuse.so.2 /lib/libfuse.so.2; do
    [[ -f "$path" ]] && { found=1; break; }
  done
  if (( !found )); then
    APP_ID="$(basename "$APPDIR")"
    echo "FUSE missing. Install it or do: \`appi fix $APP_ID --extract\`. You can then run without FUSE using the normal run command: \`appi run $APP_ID\`." >&2
  fi
fi
APPIMAGE_PATH="$APPDIR/current"
if [[ -L "$APPIMAGE_PATH" ]]; then
  APPIMAGE_PATH="$(readlink -f "$APPIMAGE_PATH")"
fi
echo "Using AppImage at $APPIMAGE_PATH" >&2
exec "$APPDIR/current" "$@"
EOF
  chmod +x "$wrapper"
  vlog "Created wrapper script: $wrapper"
}

# ---------- commands ----------

usage() {
  cat <<EOF
$PROG — User-space AppImage layout + desktop integration (no daemon, no root for normal install/run; some fixes require sudo)

USAGE:
  $PROG [--root PATH] [--dry-run] [--quiet|--verbose] <command> [args...]

COMMANDS:
  install <file.AppImage> [--id APP_ID] [--copy|--move] [--link|--no-link] [--icons|--no-icons]
      Add an AppImage under <root>/<app_id>/versions, update current symlink,
      generate a .desktop entry, and optionally create ~/.local/bin/<app_id>.

  refresh [APP_ID] [--icons|--no-icons]
      Rebuild .desktop (and icon if enabled) for one app or all apps.

  list
      Show installed apps and their current targets.

  run <APP_ID> [-- <args...>]
      Run the app's current AppImage with optional arguments.
      If an extracted version exists (from fix), uses that instead.
      Warns if FUSE is missing when running AppImage directly.

  fix <APP_ID> [--extract|--chrome-sandbox|--revert]
      Extract AppImage and fix compatibility issues (advanced/opt-in).
      With --extract, extracts AppImage to run without FUSE (no sudo required).
      With --chrome-sandbox, extracts and sets SUID on chrome-sandbox binary (requires sudo).
      With --revert, removes extracted version and reverts to AppImage.

  uninstall <APP_ID> [--purge] [--no-prompt]
      Remove desktop entry and bin link. Keeps versions by default.
      With --purge, removes <root>/<app_id> entirely.

  clean [APP_ID]
      Remove old versions from versions/ directory, keeping only the current one.
      Without APP_ID, cleans all installed apps.

OPTIONS:
  --root PATH     Override Apps root (default: ~/Apps; env: APPI_ROOT)
  --dry-run       Print what would happen, do nothing
  --quiet         Minimal output
  --verbose       More output

EXAMPLES:
  $PROG install ~/Downloads/Obsidian-1.5.12.AppImage --id obsidian
  $PROG list
  $PROG run obsidian
  $PROG refresh obsidian
  $PROG fix obsidian --extract
  $PROG fix obsidian --chrome-sandbox
  $PROG fix obsidian --revert
  $PROG uninstall obsidian
  $PROG uninstall obsidian --purge
  $PROG clean obsidian
  $PROG clean
EOF
}

cmd_install() {
  local file="${1:-}"; shift || true
  [[ -n "$file" ]] || die "install requires a path to an AppImage"
  [[ -f "$file" ]] || die "file not found: $file"

  local id=""
  local mode="copy"    # default: copy (keep original)
  local link_mode="auto"
  local icons=1

  while (( $# )); do
    case "$1" in
      --id) shift; id="${1:-}"; [[ -n "$id" ]] || die "--id requires a value" ;;
      --copy) mode="copy" ;;
      --move) mode="move" ;;
      --link) link_mode="on" ;;
      --no-link) link_mode="off" ;;
      --icons) icons=1 ;;
      --no-icons) icons=0 ;;
      *) die "Unknown install option: $1" ;;
    esac
    shift || true
  done

  if [[ -z "$id" ]]; then
    id="$(infer_app_id_from_filename "$file")"
  fi
  id="$(normalize_app_id "$id")"

  local app_dir="$ROOT/$id"
  ensure_dir "$app_dir/versions"
  ensure_dir "$app_dir/desktop"
  ensure_dir "$app_dir/icons"
  ensure_dir "$app_dir/meta"

  local base
  base="$(basename "$file")"
  [[ "$base" == *.AppImage || "$base" == *.appimage ]] || die "Not an AppImage filename (expected *.AppImage): $base"

  # normalize extension casing
  if [[ "$base" == *.appimage ]]; then
    base="${base%.appimage}.AppImage"
  fi

  # Compute checksum of source file to detect duplicates
  log "Computing checksum..."
  local source_checksum
  source_checksum="$(compute_checksum "$file")"
  vlog "Source checksum: $source_checksum"

  # Check if this exact file already exists
  local existing_file
  existing_file="$(find_existing_by_checksum "$app_dir" "$source_checksum" || true)"
  
  local dest
  local dest_basename
  if [[ -n "$existing_file" ]]; then
    log "Duplicate detected: identical file already exists as '$existing_file'"
    dest="$app_dir/versions/$existing_file"
    dest_basename="$existing_file"
    # If using --move, remove the source file since it's a duplicate
    if [[ "$mode" == "move" ]]; then
      run_cmd rm -f "$file"
      log "Removed duplicate source file"
    fi
    # Update current symlink to point to existing file
    run_cmd ln -sfn "versions/$existing_file" "$app_dir/current"
    log "Updated 'current' to point to existing file"
  else
    # No duplicate found, proceed with normal installation
    dest="$(unique_target_path "$app_dir/versions" "$base")"
    dest_basename="$(basename "$dest")"

    log "Installing '$id' into: $app_dir"
    if [[ "$mode" == "copy" ]]; then
      run_cmd cp -f "$file" "$dest"
    else
      run_cmd mv -f "$file" "$dest"
    fi
    run_cmd chmod +x "$dest"

    # Store checksum for future duplicate detection
    store_checksum "$app_dir" "$dest_basename" "$source_checksum"

    # Update current symlink (atomic-ish with ln -sfn)
    run_cmd ln -sfn "versions/$dest_basename" "$app_dir/current"
  fi

  # Desktop + icon
  if (( icons )); then
    maybe_extract_icon "$id" || true
  fi

  # If an extracted version already exists, keep it in sync with current
  if [[ -d "$app_dir/extracted" ]]; then
    if extracted_marker_matches "$app_dir" "$source_checksum"; then
      vlog "Extracted version already matches current: $id"
    else
      log "Updating extracted version to match current: $id"
      extract_appimage "$app_dir" "$dest" "$source_checksum" "$dest_basename"
      # If chrome-sandbox fix was previously applied, reapply it automatically
      if has_chrome_sandbox_fix "$app_dir"; then
        local squashfs_root="$app_dir/extracted/squashfs-root"
        log "Reapplying chrome-sandbox fix for updated version: $id"
        apply_chrome_sandbox_fix "$app_dir" "$squashfs_root" 1 || true
      fi
    fi
  fi

  ensure_run_wrapper "$id"
  write_desktop_file "$id"
  maybe_link_bin "$id" "$link_mode"

  log "Done: $id"
}

cmd_refresh() {
  local target="${1:-}"
  local icons=1

  # If first arg looks like an option, treat as no app_id
  if [[ "${target:-}" =~ ^-- ]]; then
    target=""
  else
    shift || true
  fi

  while (( $# )); do
    case "$1" in
      --icons) icons=1 ;;
      --no-icons) icons=0 ;;
      *) die "Unknown refresh option: $1" ;;
    esac
    shift || true
  done

  if [[ -n "$target" ]]; then
    local id
    id="$(normalize_app_id "$target")"
    local app_dir="$ROOT/$id"
    [[ -d "$app_dir" ]] || die "not installed: $id"
    [[ -L "$app_dir/current" || -e "$app_dir/current" ]] || die "missing current for: $id"
    if (( icons )); then maybe_extract_icon "$id" || true; fi
    ensure_run_wrapper "$id"
    write_desktop_file "$id"
    log "Refreshed: $id"
    return 0
  fi

  [[ -d "$ROOT" ]] || { log "Nothing to refresh (no root dir): $ROOT"; return 0; }

  local any=0
  for d in "$ROOT"/*; do
    [[ -d "$d" ]] || continue
    local id
    id="$(basename "$d")"
    [[ -e "$d/current" ]] || continue
    any=1
    if (( icons )); then maybe_extract_icon "$id" || true; fi
    ensure_run_wrapper "$id"
    write_desktop_file "$id"
    log "Refreshed: $id"
  done

  (( any )) || log "Nothing to refresh (no apps found)."
}

cmd_list() {
  [[ -d "$ROOT" ]] || { log "No apps root: $ROOT"; return 0; }

  local found=0
  for d in "$ROOT"/*; do
    [[ -d "$d" ]] || continue
    local id
    id="$(basename "$d")"
    local target_suffix=""
    if [[ -x "$d/extracted/squashfs-root/AppRun" ]]; then
      target_suffix=" (extracted)"
    fi
    local cur="$d/current"
    [[ -e "$cur" || -L "$cur" ]] || continue
    found=1
    local tgt=""
    if have_cmd readlink; then
      tgt="$(readlink "$cur" 2>/dev/null || true)"
    fi
    local display_name="$id"
    if [[ -n "$tgt" ]]; then
      printf "%-24s -> %s\n" "$display_name" "$tgt$target_suffix"
    else
      printf "%-24s\n" "$display_name"
    fi
  done
  (( found )) || log "No apps found under: $ROOT"
}

cmd_run() {
  local id="${1:-}"; shift || true
  [[ -n "$id" ]] || die "run requires APP_ID"
  id="$(normalize_app_id "$id")"

  # allow: appi run id -- args...
  if [[ "${1:-}" == "--" ]]; then shift || true; fi

  local app_dir="$ROOT/$id"
  local wrapper="$app_dir/run"
  [[ -f "$wrapper" ]] || die "not installed or missing wrapper: $id"

  exec "$wrapper" "$@"
}

cmd_fix() {
  local id="${1:-}"; shift || true
  [[ -n "$id" ]] || die "fix requires APP_ID"
  id="$(normalize_app_id "$id")"

  local chrome_sandbox=0
  local extract=0
  local revert=0

  while (( $# )); do
    case "$1" in
      --chrome-sandbox) chrome_sandbox=1 ;;
      --extract|--appimage-extract) extract=1 ;;
      --revert) revert=1 ;;
      *) die "Unknown fix option: $1" ;;
    esac
    shift || true
  done

  local app_dir="$ROOT/$id"
  [[ -d "$app_dir" ]] || die "not installed: $id"

  if (( revert )); then
    local extracted_dir="$app_dir/extracted"
    if [[ -d "$extracted_dir" ]]; then
      log "Reverting fix for '$id'..."
      run_cmd rm -rf "$extracted_dir"
      clear_extracted_marker "$app_dir"
      clear_chrome_sandbox_marker "$app_dir"
      ensure_run_wrapper "$id"
      write_desktop_file "$id"
      log "Reverted: $id (removed extracted version, using AppImage)"
    else
      log "Nothing to revert for: $id (no extracted version found)"
    fi
    return 0
  fi

  local current_path="$app_dir/current"
  [[ -e "$current_path" ]] || die "missing current for: $id"

  # Resolve symlink to actual AppImage
  local appimage_path
  if [[ -L "$current_path" ]]; then
    appimage_path="$(readlink -f "$current_path")"
  else
    appimage_path="$current_path"
  fi

  [[ -f "$appimage_path" ]] || die "current does not point to a file: $appimage_path"

  local appimage_checksum=""
  local appimage_basename=""
  if (( extract || chrome_sandbox )); then
    appimage_checksum="$(compute_checksum "$appimage_path")"
    appimage_basename="$(basename "$appimage_path")"
  fi

  if (( chrome_sandbox )); then
    # Security warning
    echo "⚠️  WARNING: This will set SUID root on an extracted binary." >&2
    echo "⚠️  Only proceed if you trust this AppImage." >&2
    echo "⚠️  This is a privilege-escalation surface if the binary has issues." >&2
    if (( !DRY_RUN )); then
      if [[ -t 0 ]]; then
        echo -n "Continue? [y/N] " >&2
        ans=""
        read -r ans || true
        echo >&2
        [[ "${ans,,}" == "y" || "${ans,,}" == "yes" ]] || die "Aborted by user"
      else
        die "Cannot prompt for confirmation (non-interactive terminal). Aborted for safety."
      fi
    fi

    log "Fixing chrome-sandbox for '$id'..."

    extract_appimage "$app_dir" "$appimage_path" "$appimage_checksum" "$appimage_basename"
    local extracted_dir="$app_dir/extracted"
    local squashfs_root="$extracted_dir/squashfs-root"

    apply_chrome_sandbox_fix "$app_dir" "$squashfs_root" 0

    # Update wrapper and desktop file
    ensure_run_wrapper "$id"
    write_desktop_file "$id"

    log "Fixed: $id (extracted to $extracted_dir)"
    log "Note: App will run from extracted location (no FUSE mount)"
    log "To revert: appi fix $id --revert"
  elif (( extract )); then
    log "Extracting AppImage for '$id'..."

    extract_appimage "$app_dir" "$appimage_path" "$appimage_checksum" "$appimage_basename"
    local extracted_dir="$app_dir/extracted"

    # Update wrapper and desktop file
    ensure_run_wrapper "$id"
    write_desktop_file "$id"

    log "Extracted: $id (extracted to $extracted_dir)"
    log "Note: App will run from extracted location (no FUSE mount)"
    log "To revert: appi fix $id --revert"
  else
    die "No fix option specified (use --extract, --chrome-sandbox, or --revert)"
  fi
}

cmd_uninstall() {
  local id="${1:-}"; shift || true
  [[ -n "$id" ]] || die "uninstall requires APP_ID"
  id="$(normalize_app_id "$id")"

  local purge=0
  local no_prompt=0

  while (( $# )); do
    case "$1" in
      --purge) purge=1 ;;
      --no-prompt) no_prompt=1 ;;
      *) die "Unknown uninstall option: $1" ;;
    esac
    shift || true
  done

  remove_desktop_install "$id"
  unlink_bin "$id"

  local app_dir="$ROOT/$id"
  if (( purge )); then
    if [[ -d "$app_dir" ]]; then
      if (( !no_prompt )) && (( !DRY_RUN )); then
        # Always prompt to stderr for visibility, check TTY for safety
        if [[ -t 0 ]] && [[ -t 2 ]]; then
          # Write prompt to stderr, then read from terminal
          printf "Purge '%s' (delete all versions/meta/icons)? [y/N] " "$app_dir" >&2
          ans=""
          # Read from /dev/tty to ensure we're reading from the actual terminal
          if [[ -r /dev/tty ]]; then
            read -r ans </dev/tty || ans=""
          else
            read -r ans || true
          fi
          echo >&2  # Newline after input
          [[ "${ans,,}" == "y" || "${ans,,}" == "yes" ]] || { log "Not purged."; return 0; }
        else
          # Non-interactive: skip purge for safety
          log "Not purged (non-interactive terminal). Use --no-prompt to skip confirmation."
          return 0
        fi
      fi
      run_cmd rm -rf "$app_dir"
      log "Purged: $id"
    else
      log "Nothing to purge for: $id"
    fi
  else
    log "Uninstalled integration (kept files): $id"
  fi
}

cmd_clean() {
  local target="${1:-}"

  # If first arg looks like an option, treat as no app_id
  if [[ "${target:-}" =~ ^-- ]]; then
    target=""
  fi

  if [[ -n "$target" ]]; then
    local id
    id="$(normalize_app_id "$target")"
    local app_dir="$ROOT/$id"
    [[ -d "$app_dir" ]] || die "not installed: $id"

    local current_link="$app_dir/current"
    [[ -e "$current_link" || -L "$current_link" ]] || die "missing current for: $id"

    # Resolve current symlink to find the actual version file
    local current_version=""
    if [[ -L "$current_link" ]]; then
      # Resolve relative symlink
      local link_target
      link_target="$(readlink "$current_link")"
      if [[ "$link_target" =~ ^versions/ ]]; then
        # Relative path like "versions/file.AppImage"
        current_version="$app_dir/$link_target"
      else
        # Absolute path
        current_version="$(readlink -f "$current_link")"
      fi
    else
      current_version="$current_link"
    fi

    [[ -f "$current_version" ]] || die "current does not point to a valid file: $current_version"

    local versions_dir="$app_dir/versions"
    [[ -d "$versions_dir" ]] || { log "No versions directory for: $id"; return 0; }

    local removed=0
    local current_basename
    current_basename="$(basename "$current_version")"

    # Remove all files in versions/ except the current one
    while IFS= read -r -d '' f; do
      local f_basename
      f_basename="$(basename "$f")"
      if [[ "$f_basename" != "$current_basename" ]]; then
        run_cmd rm -f "$f"
        remove_checksum_entry "$app_dir" "$f_basename"
        (( removed++ ))
        vlog "Removed old version: $f_basename"
      fi
    done < <(find "$versions_dir" -type f \( -name "*.AppImage" -o -name "*.appimage" \) -print0 2>/dev/null || true)

    if (( removed > 0 )); then
      log "Cleaned $id: removed $removed old version(s), kept $current_basename"
    else
      log "No old versions to clean for: $id"
    fi
    return 0
  fi

  # Clean all apps
  [[ -d "$ROOT" ]] || { log "Nothing to clean (no root dir): $ROOT"; return 0; }

  local any=0
  for d in "$ROOT"/*; do
    [[ -d "$d" ]] || continue
    local id
    id="$(basename "$d")"
    [[ -e "$d/current" ]] || continue
    any=1
    cmd_clean "$id"
  done

  (( any )) || log "Nothing to clean (no apps found)."
}

# ---------- global arg parsing + dispatch ----------

# Parse global options with positional shifts
ARGS=("$@")
# parse globals with manual shift
i=0
while (( i < ${#ARGS[@]} )); do
  case "${ARGS[$i]}" in
    --root) ((i++)); ROOT="${ARGS[$i]:-}"; [[ -n "$ROOT" ]] || die "--root requires a path" ;;
    --dry-run) DRY_RUN=1 ;;
    --quiet) QUIET=1 ;;
    --verbose) VERBOSE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) break ;;
  esac
  ((i++))
done
# slice remaining
REMAIN=("${ARGS[@]:$i}")
[[ "${ROOT}" == "~"* ]] && ROOT="${ROOT/#\~/$HOME}"

cmd="${REMAIN[0]:-}"
[[ -n "$cmd" ]] || { usage; exit 1; }

case "$cmd" in
  install)   cmd_install "${REMAIN[@]:1}" ;;
  refresh)   cmd_refresh "${REMAIN[@]:1}" ;;
  list)      cmd_list ;;
  run)       cmd_run "${REMAIN[@]:1}" ;;
  fix)       cmd_fix "${REMAIN[@]:1}" ;;
  uninstall) cmd_uninstall "${REMAIN[@]:1}" ;;
  clean)     cmd_clean "${REMAIN[@]:1}" ;;
  *) die "Unknown command: $cmd (try --help)" ;;
esac
