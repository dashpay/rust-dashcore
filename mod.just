# Settings and variables imported by the `Justfile` and every module

set windows-shell := ["powershell.exe", "-NoLogo", "-NoProfile", "-Command"]

python := if os_family() == "windows" { "python" } else { "python3" }
root := justfile_directory()
unix_only := "unsupported on Windows, requires Linux, macOS or WSL"
