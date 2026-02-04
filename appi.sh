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
VERSION="1.1.0"

ROOT_DEFAULT="${APPI_ROOT:-$HOME/Apps}"
ROOT="$ROOT_DEFAULT"

DRY_RUN=0
QUIET=0
VERBOSE=0
USE_COLOR=0
NO_COLOR_FLAG=0

# Used by `update` to ensure EXIT trap cleanup still works after `cmd_update` returns.
APPI_UPDATE_TMP_FILE=""

# Flag to warn once when jq is missing
JQ_MISSING_WARNED=0

# ---------- color support ----------

init_color() {
  # Enable color if:
  # 1. Output is a TTY
  # 2. NO_COLOR environment variable is not set
  # 3. --no-color flag was not provided
  if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]] && (( !NO_COLOR_FLAG )); then
    USE_COLOR=1
  else
    USE_COLOR=0
  fi

}

color_red() {
  if (( USE_COLOR )); then
    echo -e "\033[0;31m$*\033[0m"
  else
    echo "$*"
  fi
}

color_yellow() {
  if (( USE_COLOR )); then
    echo -e "\033[0;33m$*\033[0m"
  else
    echo "$*"
  fi
}

color_green() {
  if (( USE_COLOR )); then
    echo -e "\033[0;32m$*\033[0m"
  else
    echo "$*"
  fi
}

color_cyan() {
  if (( USE_COLOR )); then
    echo -e "\033[0;94m$*\033[0m"
  else
    echo "$*"
  fi
}

# ---------- logging / utils ----------

die() { echo "$(color_red "Error:") $*" >&2; exit 1; }

warn() { echo "$(color_yellow "Warning:") $*" >&2; }

success() { log "$(color_green "$*")"; }

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

# Check if unprivileged user namespaces are available
# Returns 0 if userns is available, 1 if disabled
check_userns_support() {
  unshare --user --map-root-user true 2>/dev/null
}

# Print guidance on enabling unprivileged user namespaces
# Returns 0 if userns was successfully enabled, 1 otherwise
print_userns_guidance() {
  log ""
  log "$(color_cyan "Unprivileged user namespaces are disabled on this system.")"
  log ""
  log "Modern Chromium/Electron apps prefer user namespaces for sandboxing."
  log "Enabling userns is the recommended approach (distributions have mitigations)."
  log ""

  # Detect which sysctl parameters exist to provide distribution-specific guidance
  if [[ -f /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]]; then
    # Ubuntu 23.10+ - AppArmor-based restriction
    log "$(color_yellow "Ubuntu detected (AppArmor-based restriction).")"
    log ""
    log "On Ubuntu 24.04+, the kernel allows userns by default"
    log "(kernel.unprivileged_userns_clone=1), but AppArmor restricts which"
    log "applications can use it unless they're whitelisted."
    log ""
    log "$(color_yellow "Option 1 (recommended):") Create an AppArmor profile for your app"
    log "This is the most secure approach but requires AppArmor knowledge."
    log ""
    log "$(color_yellow "Option 2:") Disable AppArmor restriction globally:"
    log "  $(color_cyan "Temporary (until reboot):")"
    log "    sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0"
    log ""
    log "  $(color_cyan "Permanent:")"
    log "    echo 'kernel.apparmor_restrict_unprivileged_userns=0' | sudo tee /etc/sysctl.d/99-userns.conf"
    log ""
    
    # Offer interactive execution of temporary command
    if (( !DRY_RUN )) && [[ -t 0 ]]; then
      echo -n "Would you like appi to enable userns temporarily (until reboot)? [y/N] " >&2
      local ans=""
      read -r ans || true
      echo >&2
      if [[ "${ans,,}" == "y" || "${ans,,}" == "yes" ]]; then
        log "Enabling unprivileged user namespaces temporarily..."
        if sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 2>/dev/null; then
          log ""
          success "Done. Electron apps should now work. Run the permanent command above to persist across reboots."
          return 0
        else
          warn "Failed to enable userns. You may need to run the command manually."
          return 1
        fi
      else
        return 1
      fi
    else
      return 1
    fi
  elif [[ -f /proc/sys/kernel/unprivileged_userns_clone ]]; then
    # Debian - kernel parameter controls userns
    log "$(color_yellow "Debian detected.")"
    log ""
    log "$(color_yellow "To enable temporarily (until reboot):")"
    log "  sudo sysctl -w kernel.unprivileged_userns_clone=1"
    log ""
    log "$(color_yellow "To enable permanently:")"
    log "  echo 'kernel.unprivileged_userns_clone=1' | sudo tee /etc/sysctl.d/99-userns.conf"
    log ""
    
    # Offer interactive execution of temporary command
    if (( !DRY_RUN )) && [[ -t 0 ]]; then
      echo -n "Would you like appi to enable userns temporarily (until reboot)? [y/N] " >&2
      local ans=""
      read -r ans || true
      echo >&2
      if [[ "${ans,,}" == "y" || "${ans,,}" == "yes" ]]; then
        log "Enabling unprivileged user namespaces temporarily..."
        if sudo sysctl -w kernel.unprivileged_userns_clone=1 2>/dev/null; then
          log ""
          success "Done. Electron apps should now work. Run the permanent command above to persist across reboots."
          return 0
        else
          warn "Failed to enable userns. You may need to run the command manually."
          return 1
        fi
      else
        return 1
      fi
    else
      return 1
    fi
  else
    # Other distributions - check user.max_user_namespaces
    log "$(color_yellow "Other distribution detected.")"
    log ""
    log "Check if user namespaces are limited:"
    log "  sysctl user.max_user_namespaces"
    log ""
    log "If the value is 0, enable it:"
    log "  sudo sysctl -w user.max_user_namespaces=10000"
    log ""
    log "Or check for distribution-specific userns restrictions."
    log ""
    log "After enabling, Chromium/Electron apps should work without SUID fixes."
    log ""
    log "$(color_yellow "Note:") The SUID chrome-sandbox fix is available as a fallback for"
    log "hardened systems (linux-hardened) or corporate environments where sysctl"
    log "changes are restricted."
    log ""
    return 1
  fi
}

is_url() {
  [[ "$1" =~ ^https?:// ]]
}

is_github_url() {
  [[ "$1" =~ ^https?://github\.com/ ]]
}

# Get the system architecture in a normalized form for AppImage matching
get_system_arch() {
  local arch
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) echo "x86_64" ;;
    aarch64|arm64) echo "aarch64" ;;
    armv7l|armhf) echo "armhf" ;;
    i686|i386) echo "i686" ;;
    *) echo "$arch" ;;
  esac
}

# Check if an AppImage filename matches or is compatible with system architecture
# Returns 0 (true) if compatible, 1 (false) if incompatible
is_appimage_arch_compatible() {
  local filename="$1"
  local system_arch
  system_arch="$(get_system_arch)"
  local filename_lower="${filename,,}"

  # Define architecture patterns to look for in filenames
  # These are common naming conventions used in AppImage releases
  local -a x86_64_patterns=("x86_64" "x86-64" "amd64" "linux64" "-64bit")
  local -a aarch64_patterns=("aarch64" "arm64" "armv8")
  local -a armhf_patterns=("armhf" "armv7" "arm32")
  local -a i686_patterns=("i686" "i386" "x86" "linux32" "-32bit")

  # Check if filename contains any architecture indicator
  local has_arch_indicator=0
  local filename_arch=""

  # Check for x86_64 patterns
  for pattern in "${x86_64_patterns[@]}"; do
    if [[ "$filename_lower" == *"$pattern"* ]]; then
      has_arch_indicator=1
      filename_arch="x86_64"
      break
    fi
  done

  # Check for aarch64 patterns
  if [[ -z "$filename_arch" ]]; then
    for pattern in "${aarch64_patterns[@]}"; do
      if [[ "$filename_lower" == *"$pattern"* ]]; then
        has_arch_indicator=1
        filename_arch="aarch64"
        break
      fi
    done
  fi

  # Check for armhf patterns
  if [[ -z "$filename_arch" ]]; then
    for pattern in "${armhf_patterns[@]}"; do
      if [[ "$filename_lower" == *"$pattern"* ]]; then
        has_arch_indicator=1
        filename_arch="armhf"
        break
      fi
    done
  fi

  # Check for i686 patterns
  if [[ -z "$filename_arch" ]]; then
    for pattern in "${i686_patterns[@]}"; do
      if [[ "$filename_lower" == *"$pattern"* ]]; then
        has_arch_indicator=1
        filename_arch="i686"
        break
      fi
    done
  fi

  # If no architecture indicator found, assume it's compatible (generic build)
  if (( !has_arch_indicator )); then
    return 0
  fi

  # Check if the detected architecture matches our system
  if [[ "$filename_arch" == "$system_arch" ]]; then
    return 0
  fi

  # x86_64 can sometimes run i686, but not the other way around
  if [[ "$system_arch" == "x86_64" && "$filename_arch" == "i686" ]]; then
    return 0
  fi

  # Not compatible
  return 1
}

# Extract a JSON string value by key (minimal jq fallback)
# Usage: json_get_string "$json" "key"
json_get_string() {
  local json="$1"
  local key="$2"
  # Try jq first (most reliable)
  if have_cmd jq; then
    echo "$json" | jq -r ".$key // empty" 2>/dev/null
    return
  fi
  # Warn once if jq is missing
  if (( !JQ_MISSING_WARNED )); then
    warn "jq not found - using portable JSON parsing fallback (install jq for better reliability)"
    JQ_MISSING_WARNED=1
  fi
  # Fallback: sed -E for portable JSON parsing (handles "key": "value")
  # Match: "key" : "value" and capture the value part
  echo "$json" | sed -E -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"([^\"]*)\".*/\\1/p" | head -n1
}

# Extract GitHub owner/repo from a GitHub URL
# Handles: github.com/owner/repo/... and strips trailing .git
extract_github_owner_repo() {
  local url="$1"
  # Extract owner/repo from URL patterns like:
  #   https://github.com/owner/repo/releases/download/v1.0/file.AppImage
  #   https://github.com/owner/repo/releases/latest/download/file.AppImage
  #   https://github.com/owner/repo
  #   https://github.com/owner/repo.git
  # Always returns owner/repo (strips .git suffix and ignores extra path segments)
  if [[ "$url" =~ github\.com/([^/]+)/([^/]+) ]]; then
    local owner="${BASH_REMATCH[1]}"
    local repo="${BASH_REMATCH[2]}"
    # Strip trailing .git if present
    repo="${repo%.git}"
    echo "$owner/$repo"
  fi
}

# Get the latest AppImage download URL from a GitHub repository
# Uses GitHub releases API to find the latest .AppImage asset
get_github_latest_appimage() {
  local source_url="$1"
  local owner_repo
  owner_repo="$(extract_github_owner_repo "$source_url")"

  if [[ -z "$owner_repo" ]]; then
    die "Could not extract owner/repo from GitHub URL: $source_url"
  fi

  local api_url="https://api.github.com/repos/$owner_repo/releases/latest"

  # Check if curl or wget is available
  local -a download_cmd=()
  if have_cmd curl; then
    download_cmd=(curl -fSL)
    # Add GitHub token if available (helps with rate limiting)
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
      download_cmd+=(-H "Authorization: token $GITHUB_TOKEN")
    fi
  elif have_cmd wget; then
    download_cmd=(wget -qO-)
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
      download_cmd+=(--header="Authorization: token $GITHUB_TOKEN")
    fi
  else
    die "Neither curl nor wget found. Cannot query GitHub API."
  fi

  vlog "Querying GitHub API: $api_url"

  # Pass URL after -- to prevent option injection
  local response
  response="$("${download_cmd[@]}" -- "$api_url" 2>/dev/null)" || {
    warn "GitHub API request failed. You may be rate-limited."
    warn "Set GITHUB_TOKEN environment variable to increase limits."
    die "Failed to query GitHub releases API"
  }

  # Find .AppImage asset URLs and filter by architecture
  local -a all_urls=()
  local system_arch
  system_arch="$(get_system_arch)"
  vlog "System architecture: $system_arch"

  if have_cmd jq; then
    # Use jq to find all .AppImage assets
    while IFS= read -r url; do
      [[ -n "$url" ]] && all_urls+=("$url")
    done < <(echo "$response" | jq -r '.assets[] | select(.name | test("\\.AppImage$"; "i")) | .browser_download_url' 2>/dev/null)
  else
    # Warn once if jq is missing
    if (( !JQ_MISSING_WARNED )); then
      warn "jq not found - using portable JSON parsing fallback (install jq for better reliability)"
      JQ_MISSING_WARNED=1
    fi
    # Fallback: sed -E for portable JSON parsing - extract browser_download_url values ending in .AppImage
    while IFS= read -r url; do
      [[ -n "$url" ]] && all_urls+=("$url")
    done < <(echo "$response" | sed -E -n 's/.*"browser_download_url"[[:space:]]*:[[:space:]]*"([^"]*\.AppImage)".*/\1/p' 2>/dev/null)
  fi

  if (( ${#all_urls[@]} == 0 )); then
    die "No .AppImage asset found in latest release of $owner_repo"
  fi

  vlog "Found ${#all_urls[@]} AppImage asset(s)"

  # Filter and prioritize by architecture
  local -a compatible_urls=()
  local -a preferred_urls=()

  for url in "${all_urls[@]}"; do
    local filename
    filename="$(basename "${url%%\?*}")"

    if is_appimage_arch_compatible "$filename"; then
      compatible_urls+=("$url")

      # Check if this one explicitly matches our architecture (preferred)
      local filename_lower="${filename,,}"
      case "$system_arch" in
        x86_64)
          if [[ "$filename_lower" == *"x86_64"* || "$filename_lower" == *"x86-64"* || "$filename_lower" == *"amd64"* ]]; then
            preferred_urls+=("$url")
          fi
          ;;
        aarch64)
          if [[ "$filename_lower" == *"aarch64"* || "$filename_lower" == *"arm64"* ]]; then
            preferred_urls+=("$url")
          fi
          ;;
        armhf)
          if [[ "$filename_lower" == *"armhf"* || "$filename_lower" == *"armv7"* ]]; then
            preferred_urls+=("$url")
          fi
          ;;
        i686)
          if [[ "$filename_lower" == *"i686"* || "$filename_lower" == *"i386"* ]]; then
            preferred_urls+=("$url")
          fi
          ;;
      esac
    else
      vlog "Skipping incompatible: $filename"
    fi
  done

  local appimage_url=""

  # Prefer explicit architecture match, then fall back to compatible (generic) ones
  if (( ${#preferred_urls[@]} > 0 )); then
    appimage_url="${preferred_urls[0]}"
    vlog "Selected architecture-matched AppImage: $(basename "${appimage_url%%\?*}")"
  elif (( ${#compatible_urls[@]} > 0 )); then
    appimage_url="${compatible_urls[0]}"
    vlog "Selected compatible AppImage: $(basename "${appimage_url%%\?*}")"
  else
    # All AppImages were for incompatible architectures
    die "No compatible AppImage found for $system_arch architecture in latest release of $owner_repo"
  fi

  echo "$appimage_url"
}

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
    checksum="$(openssl dgst -sha256 <"$file" | awk '{print $NF}' || echo "")"
    [[ -n "$checksum" ]] || die "Failed to compute checksum with openssl"
  else
    die "No checksum tool found (need sha256sum, shasum, or openssl)"
  fi
  [[ -n "$checksum" ]] || die "Checksum computation returned empty result"
  echo "$checksum"
}

download_file() {
  local url="$1"
  local output_file="$2"

  # Check if curl or wget is available
  local -a download_cmd=()
  if have_cmd curl; then
    download_cmd=(curl -fSL)
  elif have_cmd wget; then
    download_cmd=(wget -qO-)
  else
    die "Neither curl nor wget found. Cannot download from URL."
  fi

  # Download to temporary file first, then move atomically
  local tmp_file
  tmp_file="$(mktemp)" || die "Failed to create temporary file"

  if (( DRY_RUN )); then
    log "[dry-run] Would download from: $url"
    log "[dry-run] Would save to: $output_file"
    rm -f "$tmp_file"
    return 0
  fi

  log "Downloading from: $url"
  # Pass URL after -- to prevent option injection
  if ! "${download_cmd[@]}" -- "$url" >"$tmp_file"; then
    rm -f "$tmp_file"
    die "Failed to download from URL: $url"
  fi

  # Verify it's not empty
  [[ -s "$tmp_file" ]] || { rm -f "$tmp_file"; die "Downloaded file is empty"; }

  # Move to final location
  mv -f "$tmp_file" "$output_file" || { rm -f "$tmp_file"; die "Failed to save downloaded file"; }
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
      warn "chrome-sandbox not found in extracted AppImage (fix was previously applied but binary missing)"
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
  local temp_extract_dir="$extracted_dir/.extract-temp"
  local temp_squashfs_root="$temp_extract_dir/squashfs-root"

  ensure_dir "$extracted_dir"

  log "Extracting AppImage..."
  if (( DRY_RUN )); then
    log "[dry-run] extract $appimage_path to $extracted_dir"
    if [[ -n "$checksum" ]]; then
      write_extracted_marker "$app_dir" "$checksum" "$filename"
    fi
    return 0
  fi

  # Clean any previous failed extraction attempt
  rm -rf "$temp_extract_dir"
  mkdir -p "$temp_extract_dir"

  # Extract to temporary location first
  # AppImage --appimage-extract always creates "squashfs-root" in current directory
  if ! ( cd "$temp_extract_dir" && "$appimage_path" --appimage-extract >/dev/null 2>&1 ); then
    rm -rf "$temp_extract_dir"
    if [[ -d "$squashfs_root" ]]; then
      warn "Failed to extract new AppImage - keeping existing extracted version"
      return 1
    else
      die "Failed to extract AppImage (does it support --appimage-extract?)"
    fi
  fi

  # Verify extraction created squashfs-root with AppRun
  if [[ ! -d "$temp_squashfs_root" ]]; then
    rm -rf "$temp_extract_dir"
    if [[ -d "$squashfs_root" ]]; then
      warn "Extraction did not create squashfs-root - keeping existing extracted version"
      return 1
    else
      die "Extraction did not create squashfs-root"
    fi
  fi

  if [[ ! -e "$temp_squashfs_root/AppRun" ]]; then
    rm -rf "$temp_extract_dir"
    if [[ -d "$squashfs_root" ]]; then
      warn "Extracted AppImage missing AppRun - keeping existing extracted version"
      return 1
    else
      die "Extracted AppImage does not contain AppRun"
    fi
  fi

  # Extraction succeeded - now safe to remove old and swap in new
  if [[ -d "$squashfs_root" ]]; then
    log "Removing old extracted version..."
    rm -rf "$squashfs_root"
  fi

  # Move new extraction into place
  mv "$temp_squashfs_root" "$squashfs_root"
  rm -rf "$temp_extract_dir"

  if [[ -n "$checksum" ]]; then
    write_extracted_marker "$app_dir" "$checksum" "$filename"
  fi

  vlog "Extraction complete: $squashfs_root"
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
    # Use awk for literal string matching to avoid regex metacharacter issues
    awk -v fn="$filename" '!($1 ~ /^[0-9a-f]{64}$/ && $2 == fn)' "$checksum_file" >"$checksum_file.tmp" 2>/dev/null || true
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

  # Use awk for literal string matching to avoid regex metacharacter issues
  awk -v fn="$filename" '!($1 ~ /^[0-9a-f]{64}$/ && $2 == fn)' "$checksum_file" >"$checksum_file.tmp" 2>/dev/null || true
  mv -f "$checksum_file.tmp" "$checksum_file" 2>/dev/null || true
}

get_source_url_file() {
  local app_dir="$1"
  echo "$app_dir/meta/source_url.txt"
}

store_source_url() {
  local app_dir="$1"
  local url="$2"
  local url_file
  url_file="$(get_source_url_file "$app_dir")"

  if (( DRY_RUN )); then
    log "[dry-run] store source URL: $url"
    return 0
  fi

  ensure_dir "$(dirname "$url_file")"
  printf "%s\n" "$url" >"$url_file"
}

read_source_url() {
  local app_dir="$1"
  local url_file
  url_file="$(get_source_url_file "$app_dir")"
  [[ -f "$url_file" ]] || return 1
  cat "$url_file" 2>/dev/null
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

  # NOTE: Exec/TryExec are quoted to handle spaces in paths.
  # Icon paths with spaces should work without quotes per desktop file spec,
  # but we ensure proper formatting.
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
    # Icon path - desktop spec allows spaces without quotes, but ensure it's properly formatted
    content+=$'\n'"Icon=$icon_path"
  fi

  if (( DRY_RUN )); then
    log "[dry-run] write $app_copy"
    log "[dry-run] write $desktop_install"
  else
    # Write atomically via temp+mv for both files
    local tmp_app_copy
    tmp_app_copy="$(mktemp "$(dirname "$app_copy")/.desktop.XXXXXX")" || die "Failed to create temp file for desktop entry"
    printf "%s\n" "$content" >"$tmp_app_copy"
    mv -f "$tmp_app_copy" "$app_copy" || die "Failed to write desktop entry: $app_copy"

    local tmp_desktop_install
    tmp_desktop_install="$(mktemp "$(dirname "$desktop_install")/.desktop.XXXXXX")" || die "Failed to create temp file for desktop entry"
    printf "%s\n" "$content" >"$tmp_desktop_install"
    mv -f "$tmp_desktop_install" "$desktop_install" || die "Failed to write desktop entry: $desktop_install"
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
  if (( DRY_RUN )); then
    log "[dry-run] icon extract (best-effort) for $id"
    return 0
  fi

  local tmp
  tmp="$(mktemp -d)"

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
  if command -v readlink >/dev/null 2>&1; then
    SCRIPT="$(readlink "$SCRIPT")"
  else
    # Fallback: manual symlink resolution
    SCRIPT="$(ls -l "$SCRIPT" 2>/dev/null | sed -e 's/.* -> //' || echo "$SCRIPT")"
  fi
  [[ "$SCRIPT" != /* ]] && SCRIPT="$(dirname "$0")/$SCRIPT"
done
APPDIR="$(cd "$(dirname "$SCRIPT")" && pwd)"
if [[ -x "$APPDIR/extracted/squashfs-root/AppRun" ]]; then
  echo "Using extracted AppRun at $APPDIR/extracted/squashfs-root/AppRun" >&2
  # Preserve argv[0] when executing extracted AppRun
  exec -a "$0" "$APPDIR/extracted/squashfs-root/AppRun" "$@"
fi
# Check for FUSE before running AppImage
fuse_found=0
if command -v ldconfig >/dev/null 2>&1; then
  if ldconfig -p 2>/dev/null | grep -q libfuse.so.2; then
    fuse_found=1
  fi
fi
if (( !fuse_found )); then
  # Fallback check: look for libfuse.so.2 in common locations
  for path in /usr/lib/x86_64-linux-gnu/libfuse.so.2 /usr/lib/aarch64-linux-gnu/libfuse.so.2 /usr/lib/libfuse.so.2 /lib/x86_64-linux-gnu/libfuse.so.2 /lib/aarch64-linux-gnu/libfuse.so.2 /lib/libfuse.so.2; do
    [[ -f "$path" ]] && { fuse_found=1; break; }
  done
  if (( !fuse_found )); then
    APP_ID="$(basename "$APPDIR")"
    echo "FUSE missing. Install it or do: \`appi fix $APP_ID --extract\`. You can then run without FUSE using the normal run command: \`appi run $APP_ID\` (or just \`$APP_ID\` if ~/.local/bin is on PATH)." >&2
  fi
fi
APPIMAGE_PATH="$APPDIR/current"
if [[ -L "$APPIMAGE_PATH" ]]; then
  if command -v readlink >/dev/null 2>&1 && readlink -f "$APPIMAGE_PATH" >/dev/null 2>&1; then
    APPIMAGE_PATH="$(readlink -f "$APPIMAGE_PATH")"
  else
    # Fallback: manual symlink resolution
    while [[ -L "$APPIMAGE_PATH" ]]; do
      APPIMAGE_PATH="$(cd "$(dirname "$APPIMAGE_PATH")" && ls -l "$APPIMAGE_PATH" 2>/dev/null | sed -e 's/.* -> //' || echo "$APPIMAGE_PATH")"
      [[ "$APPIMAGE_PATH" != /* ]] && APPIMAGE_PATH="$(cd "$(dirname "$APPIMAGE_PATH")" && pwd)/$APPIMAGE_PATH"
    done
  fi
fi
echo "Using AppImage at $APPIMAGE_PATH" >&2
# Preserve argv[0] when executing AppImage
exec -a "$0" "$APPDIR/current" "$@"
EOF
  chmod +x "$wrapper"
  vlog "Created wrapper script: $wrapper"
}

# ---------- health check helper ----------

print_check() {
  local status="$1"  # pass, warn, error
  local message="$2"
  case "$status" in
    pass)  log "  $(color_green "[OK]") $message" ;;
    warn)  log "  $(color_yellow "[WARN]") $message" ;;
    error) log "  $(color_red "[ERR]") $message" ;;
  esac
}

# ---------- commands ----------

usage() {
  # Initialize color support if not already done (needed when called from --help)
  init_color
  cat <<EOF
$PROG — User-space AppImage layout + desktop integration (no daemon, no root for normal install/run; some fixes require sudo)

USAGE:
  $PROG [$(color_yellow "--root") PATH] [$(color_yellow "--dry-run")] [$(color_yellow "--quiet")|$(color_yellow "--verbose")] <command> [args...]

$(color_cyan "COMMANDS:")
  $(color_green "install") <file.AppImage|URL> [$(color_yellow "--id") APP_ID] [$(color_yellow "--copy")|$(color_yellow "--move")] [$(color_yellow "--link")|$(color_yellow "--no-link")] [$(color_yellow "--icons")|$(color_yellow "--no-icons")]
      Add an AppImage under <root>/<app_id>/versions, update current symlink,
      generate a .desktop entry, and optionally create ~/.local/bin/<app_id>.
      First argument can be a local file path or a URL (http:// or https://) to download from.
      If a URL is provided, it is saved as the source URL.

  $(color_green "refresh") [APP_ID] [$(color_yellow "--icons")|$(color_yellow "--no-icons")] [$(color_yellow "--source-url") URL]
      Rebuild .desktop (and icon if enabled) for one app or all apps.
      Use $(color_yellow "--source-url") to update the stored source URL for an app.

  $(color_green "list")
      Show installed apps and their current targets.

  $(color_green "switch") <APP_ID> <VERSION>
      Switch to a different version. VERSION can be exact filename or partial match.
      If an extracted version exists, it will be re-extracted automatically.

  $(color_green "info") <APP_ID>
      Show detailed information about an installed app including source URL and stored versions (current marked with *).

  $(color_green "run") <APP_ID> [-- <args...>]
      Run the app's current AppImage with optional arguments.
      If an extracted version exists (from fix), uses that instead.
      Warns if FUSE is missing when running AppImage directly.

  $(color_green "fix") <APP_ID> [$(color_yellow "--extract")|$(color_yellow "--chrome-sandbox")|$(color_yellow "--revert")]
  $(color_green "fix") $(color_yellow "--check") [APP_ID]
      Extract AppImage and fix compatibility issues (advanced/opt-in).
      With $(color_yellow "--check"), runs health checks on one or all apps.
      With $(color_yellow "--extract"), extracts AppImage to run without FUSE (no sudo required).
      With $(color_yellow "--chrome-sandbox"), fallback SUID fix for hardened systems where
      unprivileged user namespaces cannot be enabled (requires sudo). Checks userns first
      and guides users to enable it if available. Prefer enabling userns via sysctl instead.
      With $(color_yellow "--revert"), removes extracted version and reverts to AppImage.

  $(color_green "uninstall") <APP_ID> [$(color_yellow "--purge")] [$(color_yellow "--no-prompt")]
      Remove desktop entry and bin link. Keeps versions by default.
      With $(color_yellow "--purge"), removes <root>/<app_id> entirely.

  $(color_green "clean") [APP_ID] [VERSION]
      Remove old versions from versions/ directory, keeping only the current one.
      With VERSION, removes just that version (must not be current).
      Without APP_ID, cleans all installed apps.

  $(color_green "size") [APP_ID]
      Show disk usage for installed apps.
      Without APP_ID: shows total and per-app summary.
      With APP_ID: shows detailed breakdown for that app.

  $(color_green "version")
      Show version information.

  $(color_green "update") [APP_ID] [$(color_yellow "--self")] [$(color_yellow "--all")] [$(color_yellow "--force")]
      Update an installed app, appi itself, or all apps.
      With APP_ID, updates that specific app using:
        1. User script at <app_dir>/meta/update.sh (if exists)
        2. GitHub releases API (if source was from GitHub)
        3. Re-download from stored source URL
      With $(color_yellow "--self"), updates appi from GitHub.
      With $(color_yellow "--all"), updates all apps that have update sources.
      With $(color_yellow "--force"), re-downloads even if checksum matches.

$(color_cyan "OPTIONS:")
  $(color_yellow "--root") PATH     Override Apps root (default: ~/Apps; env: APPI_ROOT)
  $(color_yellow "--dry-run")       Print what would happen, do nothing
  $(color_yellow "--quiet")         Minimal output
  $(color_yellow "--verbose")       More output
  $(color_yellow "--no-color")      Disable colored output (also respects NO_COLOR env var)
  $(color_yellow "-V"), $(color_yellow "--version")   Show version information

$(color_cyan "EXAMPLES:")
  (GIMP 3.08 is an open-source image editor, used here only as an example. Check it out, it's great.)
  $PROG $(color_green "install") ~/Downloads/GIMP-3.08.AppImage $(color_yellow "--id") gimp
  $PROG $(color_green "install") https://example.com/app.AppImage $(color_yellow "--id") myapp
  $PROG $(color_green "list")
  $PROG $(color_green "info") gimp
  $PROG $(color_green "switch") gimp GIMP-3.08.AppImage
  $PROG $(color_green "run") gimp (or just "gimp" if ~/.local/bin is on PATH)
  $PROG $(color_green "refresh") gimp
  $PROG $(color_green "fix") gimp $(color_yellow "--extract")
  $PROG $(color_green "fix") gimp $(color_yellow "--chrome-sandbox")
  $PROG $(color_green "fix") gimp $(color_yellow "--revert")
  $PROG $(color_green "fix") $(color_yellow "--check")
  $PROG $(color_green "fix") $(color_yellow "--check") gimp
  $PROG $(color_green "size")
  $PROG $(color_green "size") gimp
  $PROG $(color_green "uninstall") gimp
  $PROG $(color_green "uninstall") gimp $(color_yellow "--purge")
  $PROG $(color_green "clean") gimp
  $PROG $(color_green "clean") gimp GIMP-3.08.AppImage
  $PROG $(color_green "clean")
  $PROG $(color_green "update") gimp
  $PROG $(color_green "update") $(color_yellow "--all")
  $PROG $(color_green "update") $(color_yellow "--self")
EOF
}

cmd_install() {
  local file="${1:-}"; shift || true
  [[ -n "$file" ]] || die "install requires a path to an AppImage or a URL"

  local id=""
  local mode="copy"    # default: copy (keep original)
  local link_mode="auto"
  local icons=1
  local source_url=""
  local download_url=""
  local temp_file=""

  # Parse options first
  while (( $# )); do
    case "$1" in
      --id) shift; id="${1:-}"; [[ -n "$id" ]] || die "--id requires a value" ;;
      --copy) mode="copy" ;;
      --move) mode="move" ;;
      --link) link_mode="on" ;;
      --no-link) link_mode="off" ;;
      --icons) icons=1 ;;
      --no-icons) icons=0 ;;
      --source-url) shift; source_url="${1:-}"; [[ -n "$source_url" ]] || die "--source-url requires a value" ;;
      *) die "Unknown install option: $1" ;;
    esac
    shift || true
  done

  # Determine if we need to download
  if is_url "$file"; then
    # Positional argument is a URL
    download_url="$file"
    # If --source-url was also provided, use it for metadata, otherwise use download URL
    [[ -z "$source_url" ]] && source_url="$download_url"
  elif [[ -n "$source_url" ]] && ! [[ -f "$file" ]]; then
    # --source-url provided but no file exists - download mode
    download_url="$source_url"
    # source_url already set, will be used for metadata
  fi

  # Download if needed
  if [[ -n "$download_url" ]]; then
    # Create temporary file for download
    temp_file="$(mktemp)" || die "Failed to create temporary file"
    # Cleanup temp file on exit
    trap 'rm -f "${temp_file:-}"' EXIT

    # Infer filename from URL if possible, otherwise use temp name
    local url_filename
    url_filename="$(basename "${download_url%%\?*}")"
    if [[ "$url_filename" == *.AppImage || "$url_filename" == *.appimage ]]; then
      # URL has AppImage extension, use it
      local temp_dir
      temp_dir="$(dirname "$temp_file")"
      rm -f "$temp_file"
      temp_file="$temp_dir/$url_filename"
    else
      # No extension in URL, add .AppImage
      mv -f "$temp_file" "${temp_file}.AppImage" 2>/dev/null || true
      temp_file="${temp_file}.AppImage"
    fi

    download_file "$download_url" "$temp_file"

    # Validate downloaded file is actually an AppImage
    # Check extension first (quick check)
    local downloaded_base
    downloaded_base="$(basename "$temp_file")"
    if [[ "$downloaded_base" != *.AppImage && "$downloaded_base" != *.appimage ]]; then
      rm -f "$temp_file"
      die "Downloaded file does not have AppImage extension"
    fi

    # Basic validation: check if file is executable or at least a binary
    # AppImages should be executable binaries
    if [[ ! -x "$temp_file" ]]; then
      # Make it executable (AppImages should be)
      chmod +x "$temp_file" || {
        rm -f "$temp_file"
        die "Downloaded file cannot be made executable"
      }
    fi

    file="$temp_file"
    # Clear trap since we'll handle cleanup after install
    trap - EXIT
  fi

  # Validate file exists (now it's either original file or downloaded temp file)
  [[ -f "$file" ]] || die "file not found: $file"

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
    # If it's a downloaded temp file, always remove it
    if [[ "$mode" == "move" ]] || [[ -n "$temp_file" ]]; then
      run_cmd rm -f "$file"
      if [[ -n "$temp_file" ]]; then
        log "Removed downloaded duplicate file"
      else
        log "Removed duplicate source file"
      fi
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

  # Store source URL if provided
  if [[ -n "$source_url" ]]; then
    store_source_url "$app_dir" "$source_url"
  fi

  # Clean up temporary file if we downloaded it and it still exists
  # (It may have been moved or removed in duplicate detection)
  if [[ -n "$temp_file" && -f "$temp_file" ]]; then
    run_cmd rm -f "$temp_file"
  fi

  success "Done: $id"
}

cmd_refresh() {
  local target="${1:-}"
  local icons=1
  local source_url=""

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
      --source-url) shift; source_url="${1:-}"; [[ -n "$source_url" ]] || die "--source-url requires a value" ;;
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
    if [[ -n "$source_url" ]]; then
      store_source_url "$app_dir" "$source_url"
    fi
    success "Refreshed: $id"
    return 0
  fi

  # If --source-url is provided without an app_id, it's an error
  if [[ -n "$source_url" ]]; then
    die "--source-url requires an APP_ID (cannot be used when refreshing all apps)"
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
    success "Refreshed: $id"
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

# Print "Versions:" section for an app (used by cmd_info). Id must be normalized.
print_app_versions() {
  local id="$1"
  local app_dir="$ROOT/$id"
  local versions_dir="$app_dir/versions"

  log "$(color_cyan "Versions:")"
  if [[ ! -d "$versions_dir" ]]; then
    log "  (none)"
    return 0
  fi

  local current_link="$app_dir/current"
  local current_basename=""
  if [[ -e "$current_link" || -L "$current_link" ]]; then
    if [[ -L "$current_link" ]]; then
      local link_target
      link_target="$(readlink "$current_link" 2>/dev/null || true)"
      if [[ "$link_target" =~ ^versions/ ]]; then
        current_basename="$(basename "$link_target")"
      elif [[ -n "$link_target" ]]; then
        local current_version
        current_version="$(readlink -f "$current_link" 2>/dev/null || true)"
        [[ -n "$current_version" && -f "$current_version" ]] && current_basename="$(basename "$current_version")"
      fi
    else
      current_basename="$(basename "$current_link")"
    fi
  fi

  local -a versions=()
  while IFS= read -r -d '' f; do
    versions+=("$f")
  done < <(find "$versions_dir" -type f \( -name "*.AppImage" -o -name "*.appimage" \) -print0 2>/dev/null || true)

  if (( ${#versions[@]} == 0 )); then
    log "  (none)"
    return 0
  fi

  local -a versions_sorted=()
  mapfile -t versions_sorted < <(printf '%s\n' "${versions[@]}" | sort -f)

  for f in "${versions_sorted[@]}"; do
    local base
    base="$(basename "$f")"
    if [[ -n "$current_basename" && "$base" == "$current_basename" ]]; then
      log "  * $base"
    else
      log "    $base"
    fi
  done
}

cmd_switch() {
  local id="${1:-}"
  local target="${2:-}"
  [[ -n "$id" ]] || die "switch requires APP_ID"
  [[ -n "$target" ]] || die "switch requires VERSION (filename or partial match)"
  id="$(normalize_app_id "$id")"

  local app_dir="$ROOT/$id"
  [[ -d "$app_dir" ]] || die "not installed: $id"

  local versions_dir="$app_dir/versions"
  [[ -d "$versions_dir" ]] || die "No versions directory for: $id"

  # Find matching version file
  local -a matches=()
  local -a all_versions=()
  while IFS= read -r -d '' f; do
    local base
    base="$(basename "$f")"
    all_versions+=("$base")
    # Exact match takes priority
    if [[ "$base" == "$target" ]]; then
      matches=("$base")
      break
    fi
    # Substring match (case-insensitive)
    if [[ "${base,,}" == *"${target,,}"* ]]; then
      matches+=("$base")
    fi
  done < <(find "$versions_dir" -type f \( -name "*.AppImage" -o -name "*.appimage" \) -print0 2>/dev/null || true)

  if (( ${#matches[@]} == 0 )); then
    die "No version matching '$target' found for $id"
  elif (( ${#matches[@]} > 1 )); then
    log "Multiple versions match '$target':"
    for m in "${matches[@]}"; do
      log "  $m"
    done
    die "Please be more specific"
  fi

  local match="${matches[0]}"
  local match_path="$versions_dir/$match"

  # Check if already current
  local current_link="$app_dir/current"
  if [[ -L "$current_link" ]]; then
    local link_target
    link_target="$(readlink "$current_link" 2>/dev/null || true)"
    if [[ "$link_target" == "versions/$match" ]]; then
      log "Already on version: $match"
      return 0
    fi
  fi

  # Update current symlink
  run_cmd ln -sfn "versions/$match" "$app_dir/current"
  log "Switched $id to: $match"

  # Handle extracted version (re-extract if exists, reapply chrome-sandbox if needed)
  if [[ -d "$app_dir/extracted" ]]; then
    local new_checksum
    new_checksum="$(compute_checksum "$match_path")"

    if extracted_marker_matches "$app_dir" "$new_checksum"; then
      vlog "Extracted version already matches: $match"
    else
      log "Updating extracted version to match: $match"
      extract_appimage "$app_dir" "$match_path" "$new_checksum" "$match"
      # If chrome-sandbox fix was previously applied, reapply it automatically
      if has_chrome_sandbox_fix "$app_dir"; then
        local squashfs_root="$app_dir/extracted/squashfs-root"
        log "Reapplying chrome-sandbox fix for switched version: $id"
        apply_chrome_sandbox_fix "$app_dir" "$squashfs_root" 1 || true
      fi
    fi
  fi

  success "Done"
}

cmd_info() {
  local id="${1:-}"
  [[ -n "$id" ]] || die "info requires APP_ID"
  id="$(normalize_app_id "$id")"

  local app_dir="$ROOT/$id"
  [[ -d "$app_dir" ]] || die "not installed: $id"

  local current="$app_dir/current"
  [[ -e "$current" || -L "$current" ]] || die "missing current for: $id"

  log "$(color_cyan "App:") $id"
  log "$(color_cyan "Location:") $app_dir"

  # Current version
  local tgt=""
  if [[ -L "$current" ]]; then
    tgt="$(readlink "$current" 2>/dev/null || true)"
  fi
  log "$(color_cyan "Current:") ${tgt:-$current}"

  # Extracted status
  if [[ -x "$app_dir/extracted/squashfs-root/AppRun" ]]; then
    log "$(color_cyan "Extracted:") yes"
    if has_chrome_sandbox_fix "$app_dir"; then
      log "$(color_cyan "Chrome sandbox fix:") applied"
    fi
  else
    log "$(color_cyan "Extracted:") no"
  fi

  # Update method
  local update_script="$app_dir/meta/update.sh"
  local source_url
  source_url="$(read_source_url "$app_dir" || true)"

  if [[ -x "$update_script" ]]; then
    log "$(color_cyan "Update:") custom script ($update_script)"
  elif [[ -n "$source_url" ]] && is_github_url "$source_url"; then
    local owner_repo
    owner_repo="$(extract_github_owner_repo "$source_url")"
    log "$(color_cyan "Update:") GitHub releases ($owner_repo)"
  elif [[ -n "$source_url" ]] && is_url "$source_url"; then
    log "$(color_cyan "Update:") source URL ($source_url)"
  else
    log "$(color_cyan "Update:") not configured"
  fi

  # Stored versions
  print_app_versions "$id"
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

  if (( DRY_RUN )); then
    local quoted
    printf -v quoted '%q ' "$wrapper" "$@"
    log "[dry-run] Would exec: ${quoted% }"
    return 0
  fi

  exec "$wrapper" "$@"
}

cmd_fix_check_app() {
  # Health check for a single app - sets CHECK_ERRORS and CHECK_WARNINGS
  local id="$1"
  local app_dir="$ROOT/$id"

  log "$id:"

  CHECK_ERRORS=0
  CHECK_WARNINGS=0

  # Check 1: current symlink exists
  local current_link="$app_dir/current"
  if [[ ! -e "$current_link" && ! -L "$current_link" ]]; then
    print_check error "missing current symlink"
    (( CHECK_ERRORS++ ))
  elif [[ -L "$current_link" && ! -e "$current_link" ]]; then
    print_check error "dangling current symlink (target missing)"
    (( CHECK_ERRORS++ ))
  else
    print_check pass "current symlink valid"
  fi

  # Check 2: versions directory has files
  local versions_dir="$app_dir/versions"
  local version_count=0
  if [[ -d "$versions_dir" ]]; then
    version_count="$(find "$versions_dir" -type f \( -name "*.AppImage" -o -name "*.appimage" \) 2>/dev/null | wc -l | tr -d ' ')"
  fi
  if (( version_count == 0 )); then
    print_check error "empty versions directory"
    (( CHECK_ERRORS++ ))
  fi

  # Check 3: run wrapper exists
  local wrapper="$app_dir/run"
  if [[ ! -f "$wrapper" ]]; then
    print_check warn "run wrapper missing (fix: appi refresh $id)"
    (( CHECK_WARNINGS++ ))
  else
    print_check pass "run wrapper exists"
  fi

  # Check 4: desktop entry exists
  local desktop_install="$HOME/.local/share/applications/$id.desktop"
  if [[ ! -f "$desktop_install" ]]; then
    print_check warn "desktop entry missing (fix: appi refresh $id)"
    (( CHECK_WARNINGS++ ))
  else
    print_check pass "desktop entry installed"
  fi

  # Check 5: AppImage is executable (only if current link is valid)
  if [[ -e "$current_link" ]]; then
    local appimage_path
    if [[ -L "$current_link" ]]; then
      appimage_path="$(readlink -f "$current_link" 2>/dev/null || true)"
    else
      appimage_path="$current_link"
    fi
    if [[ -f "$appimage_path" && ! -x "$appimage_path" ]]; then
      print_check warn "AppImage not executable (fix: chmod +x $appimage_path)"
      (( CHECK_WARNINGS++ ))
    elif [[ -f "$appimage_path" ]]; then
      print_check pass "AppImage executable"
    fi
  fi

  # Check 6: extracted version in sync (if extracted exists)
  local extracted_dir="$app_dir/extracted"
  local squashfs_root="$extracted_dir/squashfs-root"
  if [[ -d "$squashfs_root" ]]; then
    if [[ -e "$current_link" ]]; then
      local appimage_path
      if [[ -L "$current_link" ]]; then
        appimage_path="$(readlink -f "$current_link" 2>/dev/null || true)"
      else
        appimage_path="$current_link"
      fi
      if [[ -f "$appimage_path" ]]; then
        local current_checksum
        current_checksum="$(compute_checksum "$appimage_path" 2>/dev/null || true)"
        if [[ -n "$current_checksum" ]] && ! extracted_marker_matches "$app_dir" "$current_checksum"; then
          print_check warn "extracted out of sync (fix: appi fix $id --extract)"
          (( CHECK_WARNINGS++ ))
        else
          print_check pass "extracted version in sync"
        fi
      fi
    fi
  fi

  # Check 7: chrome-sandbox marker orphan (marker exists but no extracted dir)
  if has_chrome_sandbox_fix "$app_dir" && [[ ! -d "$squashfs_root" ]]; then
    print_check warn "chrome-sandbox marker orphan (fix: appi fix $id --revert)"
    (( CHECK_WARNINGS++ ))
  fi
}

cmd_fix() {
  local chrome_sandbox=0
  local extract=0
  local revert=0
  local check=0
  local id=""

  # Parse all arguments (options can come before or after APP_ID)
  local -a args=("$@")
  for arg in "${args[@]}"; do
    case "$arg" in
      --chrome-sandbox) chrome_sandbox=1 ;;
      --extract|--appimage-extract) extract=1 ;;
      --revert) revert=1 ;;
      --check) check=1 ;;
      -*)
        die "Unknown fix option: $arg"
        ;;
      *)
        if [[ -z "$id" ]]; then
          id="$arg"
        else
          die "Too many arguments for fix command"
        fi
        ;;
    esac
  done

  # Check mutual exclusivity
  local mode_count=$((chrome_sandbox + extract + revert + check))
  if (( mode_count > 1 )); then
    die "--check, --extract, --chrome-sandbox, and --revert are mutually exclusive"
  fi

  # Handle --check mode
  if (( check )); then
    log "Checking installed apps..."
    log ""

    local total_apps=0
    local total_errors=0
    local total_warnings=0

    # Global variables set by cmd_fix_check_app
    CHECK_ERRORS=0
    CHECK_WARNINGS=0

    if [[ -n "$id" ]]; then
      # Check specific app
      id="$(normalize_app_id "$id")"
      local app_dir="$ROOT/$id"
      [[ -d "$app_dir" ]] || die "not installed: $id"

      cmd_fix_check_app "$id"
      total_apps=1
      total_errors=$CHECK_ERRORS
      total_warnings=$CHECK_WARNINGS
    else
      # Check all apps
      [[ -d "$ROOT" ]] || { log "No apps root: $ROOT"; return 0; }

      for d in "$ROOT"/*; do
        [[ -d "$d" ]] || continue
        local app_id
        app_id="$(basename "$d")"
        [[ -e "$d/current" || -L "$d/current" ]] || continue

        total_apps=$((total_apps + 1))
        log ""
        cmd_fix_check_app "$app_id"
        total_errors=$((total_errors + CHECK_ERRORS))
        total_warnings=$((total_warnings + CHECK_WARNINGS))
      done
    fi

    log ""
    log "Summary: $total_apps app(s) checked, $total_errors error(s), $total_warnings warning(s)"
    return 0
  fi

  # Non-check modes require APP_ID
  [[ -n "$id" ]] || die "fix requires APP_ID (or use --check for health checks)"
  id="$(normalize_app_id "$id")"

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
    # Check userns support first
    log "Checking unprivileged user namespaces support..."
    if check_userns_support; then
      warn "Unprivileged user namespaces are available on this system."
      warn "The SUID chrome-sandbox fix is not needed - Chromium/Electron apps"
      warn "can use the default sandbox with user namespaces."
      log ""
      log "Consider using 'appi fix $id --extract' instead, which extracts"
      log "the AppImage without requiring SUID permissions."
      log ""
      if (( !DRY_RUN )); then
        if [[ -t 0 ]]; then
          echo -n "Do you still want to apply the SUID fix? [y/N] " >&2
          ans=""
          read -r ans || true
          echo >&2
          [[ "${ans,,}" == "y" || "${ans,,}" == "yes" ]] || {
            log "Aborted. Use 'appi fix $id --extract' for normal extraction."
            return 0
          }
        else
          die "userns is available - SUID fix not needed. Use --extract instead."
        fi
      fi
    else
      # userns is disabled - show guidance
      if print_userns_guidance; then
        # userns was successfully enabled
        log ""
        success "Unprivileged user namespaces enabled temporarily."
        log "Try running your app now. If it works, you can make it permanent"
        log "using the command shown above."
        return 0
      fi
      # Fall through to SUID prompt if declined or failed
      if (( !DRY_RUN )); then
        if [[ -t 0 ]]; then
          echo -n "Do you want to proceed with SUID fallback fix? [y/N] " >&2
          ans=""
          read -r ans || true
          echo >&2
          [[ "${ans,,}" == "y" || "${ans,,}" == "yes" ]] || {
            log "Aborted. Enable userns (see instructions above) or use 'appi fix $id --extract'."
            return 0
          }
        else
          die "userns disabled. Enable it first (see guidance above) or use --extract."
        fi
      fi
    fi

    # Security warning for SUID fix
    warn "This will set SUID root on an extracted binary."
    warn "Only proceed if you trust this AppImage."
    warn "This is a privilege-escalation surface if the binary has issues."
    warn "This is a fallback for hardened systems where userns cannot be enabled."
    if (( !DRY_RUN )); then
      if [[ -t 0 ]]; then
        echo -n "Continue with SUID fix? [y/N] " >&2
        ans=""
        read -r ans || true
        echo >&2
        [[ "${ans,,}" == "y" || "${ans,,}" == "yes" ]] || die "Aborted by user"
      else
        die "Cannot prompt for confirmation (non-interactive terminal). Aborted for safety."
      fi
    fi

    log "Applying SUID chrome-sandbox fix for '$id'..."

    extract_appimage "$app_dir" "$appimage_path" "$appimage_checksum" "$appimage_basename"
    local extracted_dir="$app_dir/extracted"
    local squashfs_root="$extracted_dir/squashfs-root"

    apply_chrome_sandbox_fix "$app_dir" "$squashfs_root" 0

    # Update wrapper and desktop file
    ensure_run_wrapper "$id"
    write_desktop_file "$id"

    success "Fixed: $id (extracted to $extracted_dir)"
    log "Note: App will run from extracted location (no FUSE mount)"
    log "To revert: appi fix $id --revert"
  elif (( extract )); then
    log "Extracting AppImage for '$id'..."

    extract_appimage "$app_dir" "$appimage_path" "$appimage_checksum" "$appimage_basename"
    local extracted_dir="$app_dir/extracted"

    # Update wrapper and desktop file
    ensure_run_wrapper "$id"
    write_desktop_file "$id"

    success "Extracted: $id (extracted to $extracted_dir)"
    log "Note: App will run from extracted location (no FUSE mount)"
    log "To revert: appi fix $id --revert"
  else
    die "No fix option specified (use --check, --extract, --chrome-sandbox, or --revert)"
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
          warn "Not purged (non-interactive terminal). Use --no-prompt to skip confirmation."
          return 0
        fi
      fi
      run_cmd rm -rf "$app_dir"
      log "Purged: $id"
    else
      log "Nothing to purge for: $id"
    fi
  else
    success "Uninstalled integration (kept files): $id"
    if [[ -d "$app_dir" ]]; then
      echo "$app_dir still exists, if you want to delete everything run: $PROG uninstall $id --purge"
    fi
  fi
}

cmd_clean() {
  local target="${1:-}"
  local version="${2:-}"
  [[ -z "${3:-}" ]] || die "clean accepts at most APP_ID and optional VERSION"

  # If first arg looks like an option, treat as no app_id
  if [[ "${target:-}" =~ ^-- ]]; then
    target=""
  fi

  if [[ -z "$target" && -n "$version" ]]; then
    die "clean requires APP_ID when VERSION is provided"
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

    local current_basename
    current_basename="$(basename "$current_version")"

    local versions_dir="$app_dir/versions"
    [[ -d "$versions_dir" ]] || { log "No versions directory for: $id"; return 0; }

    if [[ -n "$version" ]]; then
      # Remove a specific version (exact or unique partial match)
      local -a matches=()
      while IFS= read -r -d '' f; do
        local base
        base="$(basename "$f")"
        if [[ "$base" == "$version" ]]; then
          matches=("$base")
          break
        fi
        if [[ "${base,,}" == *"${version,,}"* ]]; then
          matches+=("$base")
        fi
      done < <(find "$versions_dir" -type f \( -name "*.AppImage" -o -name "*.appimage" \) -print0 2>/dev/null || true)

      if (( ${#matches[@]} == 0 )); then
        die "No version matching '$version' found for $id"
      elif (( ${#matches[@]} > 1 )); then
        log "Multiple versions match '$version':"
        for m in "${matches[@]}"; do
          log "  $m"
        done
        die "Please be more specific"
      fi

      local match="${matches[0]}"
      if [[ -n "$current_basename" && "$match" == "$current_basename" ]]; then
        die "Cannot remove current version: $match (switch to another version first)"
      fi

      run_cmd rm -f "$versions_dir/$match"
      remove_checksum_entry "$app_dir" "$match"
      log "Removed $id version: $match"
      return 0
    fi

    local removed=0

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

cmd_size() {
  local target="${1:-}"

  # Helper to get human-readable size
  get_dir_size() {
    local path="$1"
    if [[ -d "$path" ]]; then
      du -sh "$path" 2>/dev/null | cut -f1
    elif [[ -f "$path" ]]; then
      du -sh "$path" 2>/dev/null | cut -f1
    else
      echo "-"
    fi
  }

  # Helper to count files in directory
  count_files() {
    local path="$1"
    if [[ -d "$path" ]]; then
      find "$path" -type f 2>/dev/null | wc -l | tr -d ' '
    else
      echo "0"
    fi
  }

  # Helper to calculate cleanable size (non-current versions)
  get_cleanable_size() {
    local app_dir="$1"
    local versions_dir="$app_dir/versions"
    local current_link="$app_dir/current"

    [[ -d "$versions_dir" ]] || { echo "0B"; return; }

    local current_basename=""
    if [[ -L "$current_link" ]]; then
      local link_target
      link_target="$(readlink "$current_link" 2>/dev/null || true)"
      if [[ "$link_target" =~ ^versions/ ]]; then
        current_basename="$(basename "$link_target")"
      fi
    fi

    local total_bytes=0
    while IFS= read -r -d '' f; do
      local f_basename
      f_basename="$(basename "$f")"
      if [[ "$f_basename" != "$current_basename" ]]; then
        local size_bytes
        size_bytes="$(stat --printf="%s" "$f" 2>/dev/null || stat -f "%z" "$f" 2>/dev/null || echo 0)"
        total_bytes=$((total_bytes + size_bytes))
      fi
    done < <(find "$versions_dir" -type f \( -name "*.AppImage" -o -name "*.appimage" \) -print0 2>/dev/null || true)

    # Convert to human-readable
    if (( total_bytes == 0 )); then
      echo "0B"
    elif (( total_bytes < 1024 )); then
      echo "${total_bytes}B"
    elif (( total_bytes < 1048576 )); then
      echo "$((total_bytes / 1024))K"
    elif (( total_bytes < 1073741824 )); then
      echo "$((total_bytes / 1048576))M"
    else
      echo "$((total_bytes / 1073741824))G"
    fi
  }

  if [[ -n "$target" ]]; then
    # Single app detailed view
    local id
    id="$(normalize_app_id "$target")"
    local app_dir="$ROOT/$id"
    [[ -d "$app_dir" ]] || die "not installed: $id"

    log "Disk usage for: $id"
    log ""
    printf "%-20s %s\n" "COMPONENT" "SIZE"

    local versions_size versions_count
    versions_size="$(get_dir_size "$app_dir/versions")"
    versions_count="$(count_files "$app_dir/versions")"
    printf "%-20s %-8s (%s file%s)\n" "versions/" "$versions_size" "$versions_count" "$( (( versions_count == 1 )) && echo "" || echo "s")"

    local extracted_size
    extracted_size="$(get_dir_size "$app_dir/extracted")"
    printf "%-20s %s\n" "extracted/" "$extracted_size"

    local icons_size
    icons_size="$(get_dir_size "$app_dir/icons")"
    printf "%-20s %s\n" "icons/" "$icons_size"

    local meta_size
    meta_size="$(get_dir_size "$app_dir/meta")"
    printf "%-20s %s\n" "meta/" "$meta_size"

    local desktop_size
    desktop_size="$(get_dir_size "$app_dir/desktop")"
    printf "%-20s %s\n" "desktop/" "$desktop_size"

    log "-------------------------------"
    local total_size
    total_size="$(get_dir_size "$app_dir")"
    printf "%-20s %s\n" "Total:" "$total_size"

    log ""
    # Show current version
    local current_link="$app_dir/current"
    if [[ -L "$current_link" ]]; then
      local link_target
      link_target="$(readlink "$current_link" 2>/dev/null || true)"
      log "Current: $link_target"
    fi

    local cleanable
    cleanable="$(get_cleanable_size "$app_dir")"
    if [[ "$cleanable" == "0B" ]]; then
      log "Cleanable: 0B (only current version present)"
    else
      log "Cleanable: $cleanable (run 'appi clean $id' to free)"
    fi

    return 0
  fi

  # All apps overview
  [[ -d "$ROOT" ]] || { log "No apps root: $ROOT"; return 0; }

  log "Disk usage for installed apps:"
  log ""
  printf "%-20s %-8s %s\n" "APP ID" "SIZE" "CURRENT"

  local total_bytes=0
  local total_cleanable_bytes=0
  local any=0

  for d in "$ROOT"/*; do
    [[ -d "$d" ]] || continue
    local id
    id="$(basename "$d")"
    [[ -e "$d/current" || -L "$d/current" ]] || continue
    any=1

    local size
    size="$(get_dir_size "$d")"

    # Get size in bytes for total
    local size_bytes
    size_bytes="$(du -sb "$d" 2>/dev/null | cut -f1 || echo 0)"
    total_bytes=$((total_bytes + size_bytes))

    # Get current version name
    local current_name=""
    if [[ -L "$d/current" ]]; then
      local link_target
      link_target="$(readlink "$d/current" 2>/dev/null || true)"
      if [[ "$link_target" =~ ^versions/ ]]; then
        current_name="$(basename "$link_target")"
      fi
    fi

    printf "%-20s %-8s %s\n" "$id" "$size" "$current_name"

    # Calculate cleanable for this app
    local versions_dir="$d/versions"
    if [[ -d "$versions_dir" ]]; then
      while IFS= read -r -d '' f; do
        local f_basename
        f_basename="$(basename "$f")"
        if [[ "$f_basename" != "$current_name" ]]; then
          local f_bytes
          f_bytes="$(stat --printf="%s" "$f" 2>/dev/null || stat -f "%z" "$f" 2>/dev/null || echo 0)"
          total_cleanable_bytes=$((total_cleanable_bytes + f_bytes))
        fi
      done < <(find "$versions_dir" -type f \( -name "*.AppImage" -o -name "*.appimage" \) -print0 2>/dev/null || true)
    fi
  done

  if (( !any )); then
    log "No apps found under: $ROOT"
    return 0
  fi

  log ""
  # Convert total to human-readable
  local total_human
  if (( total_bytes < 1024 )); then
    total_human="${total_bytes}B"
  elif (( total_bytes < 1048576 )); then
    total_human="$((total_bytes / 1024))K"
  elif (( total_bytes < 1073741824 )); then
    total_human="$((total_bytes / 1048576))M"
  else
    # Use awk for decimal precision with GB
    total_human="$(awk "BEGIN {printf \"%.1fG\", $total_bytes / 1073741824}")"
  fi
  log "Total: $total_human"

  # Convert cleanable to human-readable
  local cleanable_human
  if (( total_cleanable_bytes == 0 )); then
    cleanable_human="0B"
  elif (( total_cleanable_bytes < 1024 )); then
    cleanable_human="${total_cleanable_bytes}B"
  elif (( total_cleanable_bytes < 1048576 )); then
    cleanable_human="$((total_cleanable_bytes / 1024))K"
  elif (( total_cleanable_bytes < 1073741824 )); then
    cleanable_human="$((total_cleanable_bytes / 1048576))M"
  else
    cleanable_human="$(awk "BEGIN {printf \"%.1fG\", $total_cleanable_bytes / 1073741824}")"
  fi

  if [[ "$cleanable_human" == "0B" ]]; then
    log "Cleanable: 0B"
  else
    log "Cleanable: $cleanable_human (run 'appi clean' to free)"
  fi
}

cmd_update_self() {
  # Simple path resolution - just use $0 and make it absolute if needed
  local script_path="$0"
  local full_script_path=""

  # If $0 is relative, make it absolute using current directory
  if [[ "$script_path" != /* ]]; then
    local cwd
    cwd="$(pwd)"
    full_script_path="$cwd/$script_path"
  else
    # Already absolute
    full_script_path="$script_path"
  fi

  # Try readlink -f to resolve symlinks if available
  if command -v readlink >/dev/null 2>&1; then
    local resolved
    resolved="$(readlink -f "$full_script_path" 2>/dev/null || true)"
    if [[ -n "$resolved" ]] && [[ -f "$resolved" ]]; then
      full_script_path="$resolved"
    fi
  fi

  # Verify the script file exists
  if [[ ! -f "$full_script_path" ]]; then
    die "Script file not found: $full_script_path"
  fi

  # Check writability only if not dry-run
  if (( !DRY_RUN )) && [[ ! -w "$full_script_path" ]]; then
    die "Script file is not writable: $full_script_path (may need sudo or chmod)"
  fi

  # GitHub raw URL (same as README)
  local github_url="https://raw.githubusercontent.com/RavioliSauce/appi/refs/heads/main/appi.sh"

  # Check if curl or wget is available
  local -a download_cmd=()
  if have_cmd curl; then
    download_cmd=(curl -fSL)
  elif have_cmd wget; then
    download_cmd=(wget -qO-)
  else
    die "Neither curl nor wget found. Cannot download update. Install one of them, or download at $github_url"
  fi

  log "Checking for updates..."
  log "Current version: $VERSION"
  log "Script location: $full_script_path"

  if (( DRY_RUN )); then
    log "[dry-run] Would download from: $github_url"
    log "[dry-run] Would replace: $full_script_path"
    log "[dry-run] Update simulation complete"
    return 0
  fi

  # Download to temporary file
  local tmp_file
  tmp_file="$(mktemp)" || die "Failed to create temporary file"

  # Cleanup on exit
  APPI_UPDATE_TMP_FILE="$tmp_file"
  trap 'rm -f "${APPI_UPDATE_TMP_FILE:-}"' EXIT

  log "Downloading latest version from GitHub..."

  # Download the new version - pass URL after -- to prevent option injection
  if ! "${download_cmd[@]}" -- "$github_url" >"$tmp_file"; then
    die "Failed to download update from GitHub"
  fi

  # Verify it's a valid bash script (basic check)
  if ! head -n 1 "$tmp_file" | grep -q "^#!/usr/bin/env bash"; then
    die "Downloaded file does not appear to be a valid bash script"
  fi

  # Preserve executable permissions
  chmod +x "$tmp_file"

  # Get new version for comparison
  local new_version
  new_version="$(grep -m1 "^VERSION=" "$tmp_file" 2>/dev/null | cut -d'"' -f2 || echo "unknown")"

  if [[ "$new_version" == "$VERSION" ]]; then
    log "Already up to date (version $VERSION)"
    rm -f "$tmp_file"
    # Disable trap before clearing variable to avoid edge-case cleanup issues
    trap - EXIT
    APPI_UPDATE_TMP_FILE=""
    return 0
  fi

  log "New version available: $new_version"

  # Optional integrity check (user-provided)
  if [[ -n "${APPI_UPDATE_SHA256:-}" ]]; then
    local new_sha
    new_sha="$(compute_checksum "$tmp_file")"
    if [[ "${APPI_UPDATE_SHA256,,}" != "${new_sha,,}" ]]; then
      die "Update checksum mismatch (expected: $APPI_UPDATE_SHA256, got: $new_sha)"
    fi
    vlog "Update checksum verified: $new_sha"
  fi

  # Replace the script atomically
  if ! mv -f "$tmp_file" "$full_script_path"; then
    die "Failed to replace script (may need write permissions)"
  fi

  # Disable trap before clearing variable to avoid edge-case cleanup issues
  trap - EXIT
  APPI_UPDATE_TMP_FILE=""

  success "Update complete! Updated from $VERSION to $new_version"
  log "Run '$PROG version' to verify"
}

cmd_update_app() {
  local id="$1"
  local force="${2:-0}"

  id="$(normalize_app_id "$id")"
  local app_dir="$ROOT/$id"

  [[ -d "$app_dir" ]] || die "not installed: $id"
  [[ -e "$app_dir/current" || -L "$app_dir/current" ]] || die "missing current for: $id"

  log "Checking for updates: $id"

  local download_url=""
  local update_script="$app_dir/meta/update.sh"

  # 1. Try user-provided update script
  if [[ -x "$update_script" ]]; then
    vlog "Running update script: $update_script"
    download_url="$("$update_script" 2>&1)" || die "Update script failed for $id"
    download_url="$(echo "$download_url" | tail -n1)"  # Take last line as URL
    if [[ -z "$download_url" ]]; then
      die "Update script returned empty URL for $id"
    fi
    vlog "Update script returned: $download_url"
  else
    # 2. Try stored source URL
    local source_url
    source_url="$(read_source_url "$app_dir" 2>/dev/null || true)"

    if [[ -z "$source_url" ]]; then
      die "No update source for $id. Add an update script at $app_dir/meta/update.sh or install with a source URL."
    fi

    vlog "Source URL: $source_url"

    # 3. Check if it's a GitHub URL
    if is_github_url "$source_url"; then
      log "Fetching latest release from GitHub..."
      download_url="$(get_github_latest_appimage "$source_url")"
      vlog "GitHub latest: $download_url"
    else
      # 4. Use source URL directly (may be a "latest" URL or static)
      download_url="$source_url"
      vlog "Using direct URL: $download_url"
    fi
  fi

  # Validate URL
  if ! is_url "$download_url"; then
    die "Invalid download URL: $download_url"
  fi

  # Get current version checksum for comparison
  local current_path="$app_dir/current"
  local current_checksum=""
  if [[ -e "$current_path" ]]; then
    local resolved_current
    if [[ -L "$current_path" ]]; then
      resolved_current="$(readlink -f "$current_path")"
    else
      resolved_current="$current_path"
    fi
    if [[ -f "$resolved_current" ]]; then
      current_checksum="$(compute_checksum "$resolved_current")"
      vlog "Current checksum: $current_checksum"
    fi
  fi

  # Download to temporary file
  local tmp_file
  tmp_file="$(mktemp)" || die "Failed to create temporary file"

  # Cleanup on exit
  local cleanup_file="$tmp_file"
  trap 'rm -f "$cleanup_file"' EXIT

  # Infer filename from URL
  local url_filename
  url_filename="$(basename "${download_url%%\?*}")"
  if [[ "$url_filename" == *.AppImage || "$url_filename" == *.appimage ]]; then
    local tmp_dir
    tmp_dir="$(dirname "$tmp_file")"
    rm -f "$tmp_file"
    tmp_file="$tmp_dir/$url_filename"
    cleanup_file="$tmp_file"
  else
    mv -f "$tmp_file" "${tmp_file}.AppImage" 2>/dev/null || true
    tmp_file="${tmp_file}.AppImage"
    cleanup_file="$tmp_file"
  fi

  if (( DRY_RUN )); then
    log "[dry-run] Would download from: $download_url"
    log "[dry-run] Would install to: $app_dir"
    rm -f "$cleanup_file"
    trap - EXIT
    return 0
  fi

  download_file "$download_url" "$tmp_file"
  chmod +x "$tmp_file"

  # Compare checksums
  local new_checksum
  new_checksum="$(compute_checksum "$tmp_file")"
  vlog "New checksum: $new_checksum"

  if [[ -n "$current_checksum" && "$current_checksum" == "$new_checksum" ]] && (( !force )); then
    log "Already up to date: $id"
    rm -f "$tmp_file"
    trap - EXIT
    return 0
  fi

  # Install the new version using existing install logic
  log "Installing update for $id..."

  # Clear trap before calling install (it manages its own cleanup)
  trap - EXIT

  # Call install with the downloaded file
  cmd_install "$tmp_file" --id "$id" --move

  success "Updated: $id"
}

cmd_update() {
  local do_self=0
  local do_all=0
  local force=0
  local app_id=""

  # Parse arguments
  while (( $# )); do
    case "$1" in
      --self) do_self=1 ;;
      --all) do_all=1 ;;
      --force) force=1 ;;
      -*)
        die "Unknown update option: $1"
        ;;
      *)
        if [[ -z "$app_id" ]]; then
          app_id="$1"
        else
          die "Too many arguments for update command"
        fi
        ;;
    esac
    shift || true
  done

  # Dispatch based on arguments
  if (( do_self )); then
    if [[ -n "$app_id" ]] || (( do_all )); then
      die "--self cannot be combined with APP_ID or --all"
    fi
    cmd_update_self
    return 0
  fi

  if (( do_all )); then
    if [[ -n "$app_id" ]]; then
      die "--all cannot be combined with APP_ID"
    fi

    [[ -d "$ROOT" ]] || { log "No apps root: $ROOT"; return 0; }

    local any=0
    local updated=0
    local failed=0
    for d in "$ROOT"/*; do
      [[ -d "$d" ]] || continue
      local id
      id="$(basename "$d")"
      [[ -e "$d/current" ]] || continue

      # Check if app has an update source
      local has_source=0
      if [[ -x "$d/meta/update.sh" ]]; then
        has_source=1
      elif [[ -f "$d/meta/source_url.txt" ]]; then
        has_source=1
      fi

      if (( !has_source )); then
        vlog "Skipping $id (no update source)"
        continue
      fi

      any=1
      log ""
      log "$(color_cyan "=== Updating: $id ===")"
      if cmd_update_app "$id" "$force" 2>&1; then
        (( updated++ ))
      else
        warn "Failed to update: $id"
        (( failed++ ))
      fi
    done

    log ""
    if (( any )); then
      log "Update complete: $updated succeeded, $failed failed"
    else
      log "No apps with update sources found."
    fi
    return 0
  fi

  if [[ -n "$app_id" ]]; then
    cmd_update_app "$app_id" "$force"
    return 0
  fi

  # No arguments - show usage hint
  die "update requires APP_ID, --self, or --all (try: $PROG update --help)"
}

# ---------- global arg parsing + dispatch ----------

# Parse global options with positional shifts
ARGS=("$@")
# Check for --no-color early (before usage() might be called)
for arg in "${ARGS[@]}"; do
  [[ "$arg" == "--no-color" ]] && NO_COLOR_FLAG=1 && break
done
# parse globals with manual shift
i=0
while (( i < ${#ARGS[@]} )); do
  case "${ARGS[$i]}" in
    --root) i=$((i+1)); ROOT="${ARGS[$i]:-}"; [[ -n "$ROOT" ]] || die "--root requires a path" ;;
    --dry-run) DRY_RUN=1 ;;
    --quiet) QUIET=1 ;;
    --verbose) VERBOSE=1 ;;
    --no-color) NO_COLOR_FLAG=1 ;;
    -h|--help) usage; exit 0 ;;
    -V|--version) echo "$PROG $VERSION"; exit 0 ;;
    *) break ;;
  esac
  i=$((i+1))
done
# slice remaining
REMAIN=("${ARGS[@]:$i}")
[[ "${ROOT}" == "~"* ]] && ROOT="${ROOT/#\~/$HOME}"

# Initialize color support after parsing --no-color flag
init_color

cmd="${REMAIN[0]:-}"
[[ -n "$cmd" ]] || { usage; exit 1; }

case "$cmd" in
  install)   cmd_install "${REMAIN[@]:1}" ;;
  refresh)   cmd_refresh "${REMAIN[@]:1}" ;;
  list)      cmd_list ;;
  switch)    cmd_switch "${REMAIN[@]:1}" ;;
  info)      cmd_info "${REMAIN[@]:1}" ;;
  run)       cmd_run "${REMAIN[@]:1}" ;;
  fix)       cmd_fix "${REMAIN[@]:1}" ;;
  size)      cmd_size "${REMAIN[@]:1}" ;;
  uninstall) cmd_uninstall "${REMAIN[@]:1}" ;;
  clean)     cmd_clean "${REMAIN[@]:1}" ;;
  version)   echo "$PROG $VERSION" ;;
  update)    cmd_update "${REMAIN[@]:1}" ;;
  *) die "Unknown command: $cmd (try --help)" ;;
esac
