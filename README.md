# appi

A single bash script to help maintain your AppImages. Organizes apps in `~/Apps/`, creates desktop launchers, and manages versions without daemons or complexity.

## Features

- Organized storage in `~/Apps/<app_id>/versions/`
- Automatic desktop integration
- Version management with SHA256 deduplication

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

```bash
appi install ~/Downloads/Obsidian-1.5.12.AppImage --id obsidian
```

When installing, appi computes SHA256 checksums to detect duplicate files. If you install the same AppImage twice, it will update the `current` symlink to the existing file instead of creating a duplicate copy.

Defaults:

* `--copy` (keeps original file)
* `--icons` (best-effort)
* `--link` only if `~/.local/bin` exists (auto)

#### List installed apps

```bash
appi list
```

#### Run an app by stable ID

```bash
appi run obsidian
```

#### Refresh desktop entry / icon

```bash
appi refresh obsidian
appi refresh        # refresh all
```

#### Uninstall (keep versions by default)

```bash
appi uninstall obsidian
```

#### Purge everything for an app

```bash
appi uninstall obsidian --purge
```

#### Clean old versions

Remove old versions from `versions/` directory, keeping only the current one:

```bash
appi clean obsidian
appi clean        # clean all apps
```

This removes all AppImage files in `versions/` except the one that `current` points to, freeing up disk space.

#### Fix compatibility issues

Use the `fix` command to extract the AppImage and fix compatibility issues:

**Extract AppImage (no FUSE required):**

```bash
appi fix obsidian --extract
```

This extracts the AppImage to `~/Apps/<app_id>/extracted/` so it can run without FUSE. No sudo required.

**Fix Chrome/Electron sandbox (requires sudo):**

Ubuntu 23.10+ restricts unprivileged user namespaces by default (`kernel.unprivileged_userns_clone=0`), which prevents Chromium/Electron apps from using their default sandbox. As a workaround, these apps must use the legacy SUID sandbox instead. The `chrome-sandbox` binary needs root ownership and SUID bit (4755) to function.

**Note:** Alternatively, you can enable unprivileged user namespaces system-wide by setting `kernel.unprivileged_userns_clone=1` via sysctl (requires root), but this reduces system security. The `--chrome-sandbox` fix is a safer per-app workaround.

```bash
appi fix obsidian --chrome-sandbox
```

This will:
- Extract the AppImage to `~/Apps/<app_id>/extracted/`
- Set SUID permissions on `chrome-sandbox` (requires sudo)
- Update desktop entries to use the extracted version
- Future runs will automatically use the extracted version (no FUSE mount)

**Revert to AppImage:**

```bash
appi fix obsidian --revert
```

Removes the extracted version and reverts to using the AppImage directly.

## Notes / limitations

* `app_id` is restricted to: lowercase letters, digits, dashes (e.g. `obs-studio`)
* If your root path contains spaces, some desktop environments may not parse Exec/Icon perfectly.
* AppImages using Chrome/Electron sandbox may fail when mounted via FUSE. Use `appi fix <app_id> --chrome-sandbox` to extract and fix.
