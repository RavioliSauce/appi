# appi

A single bash script to help maintain your AppImages. Organizes apps in `~/Apps/`, creates desktop launchers, and manages versions without daemons or complexity.

## Features

- Organized storage in `~/Apps/<app_id>/versions/`
- Automatic desktop integration
- Version management with SHA256 deduplication
- **Direct URL download support** - install AppImages directly from URLs
- **App update capability** - update installed apps automatically via scripts, GitHub releases, or source URLs
- Self-update capability via `appi update --self`
- Color-coded output (respects `NO_COLOR` env var and `--no-color` flag)

## Quickstart

Download and install directly from the repo (if you trust me...):

```bash
mkdir -p ~/.local/bin
curl -o ~/.local/bin/appi https://raw.githubusercontent.com/RavioliSauce/appi/refs/heads/main/appi.sh
chmod +x ~/.local/bin/appi
```

(or just copy the text in `appi.sh` and paste it into ~/.local/bin/appi using nano or any other text editor.)


## Advanced manual

### Usage

```bash
appi --help
```

#### Install an AppImage

*(GIMP 3.08 is an open-source image editor, used here only as an example.)*

You can install from a local file or download directly from a URL:

```bash
# Install from local file
appi install ~/Downloads/GIMP-3.08.AppImage --id gimp

# Install directly from URL
appi install https://example.com/app.AppImage --id myapp

# URL can be a "latest" link too
appi install https://example.com/download/latest --id myapp
```

#### List installed apps

```bash
appi list
```

#### Switch to a different version

```bash
appi switch gimp GIMP-3.08.AppImage
appi switch gimp 3.08  # partial match works too
```

If the app was extracted (via `appi fix --extract`), the extracted version is automatically updated to match.

#### View app info

```bash
appi info gimp
```

Shows detailed information about an installed app:
- App ID and location
- Current version file path
- Extraction status (whether AppImage is extracted or using FUSE)
- Chrome sandbox fix status (if applied)
- Source URL (if set during installation)
- Stored versions (current marked with `*`)

#### Run an app by stable ID

```bash
appi run gimp  # (or just `gimp` if ~/.local/bin is on PATH)
```

#### Refresh desktop entry / icon

```bash
appi refresh gimp
appi refresh        # refresh all
appi refresh gimp --source-url https://example.com/new-url  # update source URL
```

#### Uninstall (keep versions by default)

```bash
appi uninstall gimp
```

#### Purge everything for an app

```bash
appi uninstall gimp --purge
```

#### Clean old versions

Remove old versions from `versions/` directory, keeping only the current one:

```bash
appi clean gimp
appi clean        # clean all apps
```

Remove a specific version (must not be current):

```bash
appi clean gimp GIMP-3.08.AppImage
```

This removes AppImage files in `versions/` and updates the checksum database to remove entries for deleted files.

#### Update apps

The `update` command can update individual apps, all apps, or appi itself.

**Update a specific app:**

```bash
appi update gimp
```

The update command uses the following resolution chain:
1. **User script** - If `<app_dir>/meta/update.sh` exists and is executable, it runs the script and uses its output as the download URL
2. **GitHub releases** - If the stored source URL is from GitHub, it automatically queries the GitHub releases API for the latest `.AppImage` asset
3. **Source URL** - Falls back to re-downloading from the stored source URL

**Update all apps:**

```bash
appi update --all
```

Updates all installed apps that have an update source (script or source URL). Skips apps without update sources.

**Update appi itself:**

```bash
appi update --self
```

Downloads and installs the latest version of `appi` from GitHub, replacing the current script. The update command:
- Checks for updates from the repository
- Downloads the latest version
- Verifies it's a valid bash script
- Optionally verifies checksum if `APPI_UPDATE_SHA256` environment variable is set
- Atomically replaces the current script

**Force re-download:**

```bash
appi update gimp --force
```

Re-downloads and installs even if the checksum matches the current version.

**Creating update scripts:**

For apps that don't use GitHub releases (like Cursor), you can create a custom update script at `<app_dir>/meta/update.sh`. The script must:
- Be executable (`chmod +x`)
- Output a single download URL to stdout
- Exit with code 0 on success, non-zero on failure
- Send errors/logs to stderr

Example for Cursor:

```bash
#!/bin/bash
curl -fsSL "https://cursor.com/api/download?platform=linux-x64&releaseTrack=latest" | jq -r '.downloadUrl'
```

**GitHub integration:**

When installing from a GitHub URL, appi automatically detects it and can use the GitHub releases API for updates. You can set the `GITHUB_TOKEN` environment variable to increase API rate limits:

```bash
export GITHUB_TOKEN=your_token_here
appi update gimp
```

**Note:** The script must be writable for self-update to succeed. If installed in a system directory, you may need to use `sudo`.

#### Fix compatibility issues

Use the `fix` command to extract the AppImage and fix compatibility issues:

**Extract AppImage (no FUSE required):**

```bash
appi fix gimp --extract
```

This extracts the AppImage to `~/Apps/<app_id>/extracted/` so it can run without FUSE. No sudo required.

**Chrome/Electron sandbox support:**

Modern Chromium/Electron apps use unprivileged user namespaces for sandboxing. Different distributions handle userns restrictions differently:

**Ubuntu 24.04+ situation:**
- `kernel.unprivileged_userns_clone=1` (enabled by default) - Kernel allows userns ✓
- `kernel.apparmor_restrict_unprivileged_userns=1` (restricted by default) - AppArmor blocks it unless app is whitelisted ✗

The kernel permits userns, but AppArmor gates access to it. Most Electron AppImages aren't in Ubuntu's whitelist, so they fail despite `clone=1`.

**Preferred solution: Enable unprivileged user namespaces**

The `appi fix` command automatically detects your distribution and provides appropriate guidance. Distributions have implemented mitigations for userns vulnerabilities (Ubuntu's AppArmor-based restrictions, kernel hardening), making userns the recommended approach.

**Ubuntu (AppArmor-based restriction):**
- **Option 1 (recommended):** Create an AppArmor profile for your app (most secure, requires AppArmor knowledge)
- **Option 2:** Disable AppArmor restriction globally:
  ```bash
  # Temporary (until reboot)
  sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
  
  # Permanent
  echo 'kernel.apparmor_restrict_unprivileged_userns=0' | sudo tee /etc/sysctl.d/99-userns.conf
  ```

**Debian:**
```bash
# Temporary (until reboot)
sudo sysctl -w kernel.unprivileged_userns_clone=1

# Permanent
echo 'kernel.unprivileged_userns_clone=1' | sudo tee /etc/sysctl.d/99-userns.conf
```

**Other distributions:**
Check `user.max_user_namespaces` sysctl or distribution-specific restrictions.

After enabling, Chromium/Electron apps should work without any fixes. The `appi fix` command will automatically detect if userns is available and guide you accordingly.

**Fallback: SUID chrome-sandbox fix (for hardened systems)**

For systems where userns cannot be enabled (linux-hardened kernel, corporate environments with locked sysctl), you can use the SUID fallback:

```bash
appi fix gimp --chrome-sandbox
```

This will:
- Check userns support first and guide you to enable it if available
- Extract the AppImage to `~/Apps/<app_id>/extracted/`
- Set SUID permissions on `chrome-sandbox` (requires sudo)
- Update desktop entries to use the extracted version
- Future runs will automatically use the extracted version (no FUSE mount)

**Note:** The SUID fix is a privilege-escalation surface and should only be used when userns cannot be enabled. The `--chrome-sandbox` option will warn you if userns is available and suggest using `--extract` instead.

**Revert to AppImage:**

```bash
appi fix gimp --revert
```

Removes the extracted version and reverts to using the AppImage directly.

## Options

### Color output

By default, `appi` uses colored output for better readability (errors in red, warnings in yellow, success messages in green). Colors are automatically disabled when output is piped or redirected.

You can disable colors explicitly:
- Use `--no-color` flag
- Set `NO_COLOR` environment variable

```bash
appi --no-color list
NO_COLOR=1 appi install file.AppImage
```

### Other options

- `--root PATH` - Override the default Apps root directory (default: `~/Apps`, or `$APPI_ROOT` env var)
- `--dry-run` - Show what would happen without making changes
- `--quiet` - Minimal output
- `--verbose` - More detailed output

## Notes / limitations

* `app_id` is restricted to: lowercase letters, digits, dashes (e.g. `obs-studio`)
* If your root path contains spaces, some desktop environments may not parse Exec/Icon perfectly.
* AppImages using Chrome/Electron sandbox may fail when unprivileged user namespaces are disabled. Enable userns via sysctl (see sandbox section above) or use `appi fix <app_id> --extract` to extract without FUSE. The `--chrome-sandbox` SUID fix is available as a fallback for hardened systems.
* **Duplicate detection:** appi uses SHA256 checksums to detect duplicate files. Installing the same AppImage twice (even with different filenames or sources) will reuse the existing file instead of creating a duplicate copy.
* **Source URL tracking:** When installing from a URL, appi automatically stores it as the source URL (shown in `appi info`). For local files, use `--source-url` to record the download location. Source URLs are used by the `update` command to automatically fetch new versions.
* **Install defaults:** `install` uses `--copy` (keeps original file), `--icons` (best-effort icon extraction), and `--link` (only if `~/.local/bin` exists).
