# Release Process

This document describes the process for creating a new release of ntttcp.

## Prerequisites

- Ensure all changes are merged to the `main` branch
- Verify that the CI build workflow has completed successfully for the latest commit
- Ensure you have appropriate permissions to create releases in the GitHub repository

## Release Steps

### 1. Create a GitHub Release

1. Go to the [Releases page](https://github.com/microsoft/ntttcp/releases) in the GitHub repository
2. Click **"Draft a new release"**
3. Create a new tag for the release (e.g., `v5.x.x`)
4. Set the release title (e.g., "ntttcp v5.x.x")
5. Write release notes describing the changes, fixes, and new features

### 2. Download Build Artifacts from CI

1. Go to the [Actions tab](https://github.com/microsoft/ntttcp/actions/workflows/build.yml) in the GitHub repository
2. Find the latest successful build workflow run for the `main` branch
3. Download the following artifacts from the workflow run:
   - `bin-x64` - Contains the x64 binaries
   - `bin-ARM64` - Contains the ARM64 binaries

### 3. Extract and Prepare Release Files

After downloading the artifacts, extract them and locate the following files:

#### For x64:
- `build/bin/x64/Release/ntttcp.exe`
- `build/bin/x64/Release/ntttcp.pdb`

#### For ARM64:
- `build/bin/ARM64/Release/ntttcp.exe`
- `build/bin/ARM64/Release/ntttcp.pdb`

Rename the files to include the architecture in the filename for clarity:
- `ntttcp-x64.exe` and `ntttcp-x64.pdb`
- `ntttcp-arm64.exe` and `ntttcp-arm64.pdb`

### 4. Attach Files to the Release

1. Return to the draft release you created in step 1
2. Attach all the prepared files (both .exe and .pdb for x64 and ARM64):
   - `ntttcp-x64.exe`
   - `ntttcp-x64.pdb`
   - `ntttcp-arm64.exe`
   - `ntttcp-arm64.pdb`
3. Review the release notes and attached files
4. Click **"Publish release"**

## Important Notes

- **Always include both .exe and .pdb files** - The .pdb files are essential for debugging and should always be included in releases
- **Include both x64 and ARM64 builds** - Ensure both architectures are represented in each release
- **Verify file integrity** - Before publishing, verify that the downloaded files are from the correct build and are not corrupted
- **Tag naming convention** - Use semantic versioning for tags (e.g., v5.0.0, v5.1.0, v5.1.1)

## Post-Release

After publishing the release:
1. Verify that all files are downloadable and not corrupted
2. Announce the release to relevant channels if needed
3. Close any related issues or pull requests that were addressed in this release
