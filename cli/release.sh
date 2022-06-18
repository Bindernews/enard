#!/bin/bash

# Github actions release script.
# Assumes GITHUB_TOKEN and OS_NAME are set as 
set -euo pipefail
NAME="enard-cli"
# Determine if we're on windows
IS_WIN=$([[ "$OS_NAME" =~ "windows-" ]] || "false")
# Get the release tag from github ref
tag="${GITHUB_REF#refs/tags/}"
# Strip the version from the OS name
os_name="${OS_NAME%-latest}"
# Full name of the zip file
zip_name="${NAME}_${tag}_${os_name}.zip"
# Determine the executable file name and extension
exe_file="${NAME}"
if $IS_WIN; then
  exe_file="${exe_file}.exe"
fi
# Build, zip, and upload to the tagged release
cargo build --release
mv "target/release/${exe_file}" ${exe_file}
if $IS_WIN; then
  7z a -tzip ${zip_name} ${exe_file}
else
  zip ${zip_name} ${exe_file}
fi
gh release upload "${tag}" "${zip_name}" --clobber
