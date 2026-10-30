# Windows Package Manager (winget) Submission & Installation Guide

The manifests in this folder conform to the official Microsoft WinGet Package Manager schema (v1.6.0) and have passed `winget validate`.

### 1. Test Local Installation via WinGet
You can test installing ProDiscover right now on your PC using the validated manifest:
```cmd
winget install --manifest manifests\winget
```
WinGet will download the installer from GitHub Releases, verify the SHA256 checksum, and silently execute the setup wizard with administrative permissions.

### 2. Publishing to the Official Microsoft WinGet Repository
To make ProDiscover installable worldwide via `winget install TechnologyPathways.ProDiscover`:

#### Method A: Using WingetCreate CLI (Recommended)
1. Install the official Microsoft WingetCreate tool:
   ```cmd
   winget install Microsoft.WingetCreate
   ```
2. Submit the package:
   ```cmd
   wingetcreate submit https://github.com/cid-moosa/prodiscover/releases/download/v1.0.0/ProDiscover_Setup.exe
   ```
3. Enter your GitHub Personal Access Token (PAT) when prompted. WingetCreate will automatically fork `microsoft/winget-pkgs`, commit the manifest, and open a PR.

#### Method B: Manual GitHub Pull Request
1. Fork `https://github.com/microsoft/winget-pkgs`.
2. Create a folder in your fork:
   `manifests/t/TechnologyPathways/ProDiscover/7.0.0.3/`
3. Copy the 3 YAML files from `manifests/winget/` into that folder:
   - `TechnologyPathways.ProDiscover.yaml`
   - `TechnologyPathways.ProDiscover.installer.yaml`
   - `TechnologyPathways.ProDiscover.locale.en-US.yaml`
4. Commit and open a Pull Request against `microsoft/winget-pkgs:master`.
5. Microsoft's validation bots will run automated install/uninstall tests and merge the PR within 24-48 hours.
