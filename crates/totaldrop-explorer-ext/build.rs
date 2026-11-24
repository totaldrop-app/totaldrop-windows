// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Compiles `resources/explorer_ext.rc` (embedding `TotalDrop.ico` as Win32
//! icon resource ID `101`) into `totaldrop_explorer_ext.dll` when targeting
//! Windows (`CARGO_CFG_TARGET_OS == "windows"`).

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    println!("cargo::rerun-if-changed=resources/explorer_ext.rc");
    println!("cargo::rerun-if-changed=../../ui-winui3-fluent2/Assets/TotalDrop.ico");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return ExitCode::SUCCESS;
    }

    let Ok(manifest_dir) = env::var("CARGO_MANIFEST_DIR").map(PathBuf::from) else {
        println!("cargo::error=CARGO_MANIFEST_DIR is not set");
        return ExitCode::FAILURE;
    };
    let Ok(out_dir) = env::var("OUT_DIR").map(PathBuf::from) else {
        println!("cargo::error=OUT_DIR is not set");
        return ExitCode::FAILURE;
    };

    let rc_script = manifest_dir.join("resources").join("explorer_ext.rc");
    if !rc_script.is_file() {
        println!(
            "cargo::error=Missing Explorer icon resource script at {}",
            rc_script.display()
        );
        return ExitCode::FAILURE;
    }

    let assets_dir = manifest_dir
        .join("..")
        .join("..")
        .join("ui-winui3-fluent2")
        .join("Assets");
    let icon_path = assets_dir.join("TotalDrop.ico");
    if !icon_path.is_file() {
        println!(
            "cargo::error=Missing TotalDrop.ico required for icon resource 101 at {}",
            icon_path.display()
        );
        return ExitCode::FAILURE;
    }

    let Some(rc_exe) = locate_rc_exe() else {
        println!(
            "cargo::error=Windows SDK rc.exe not found in WindowsSdkDir, Windows Kits 10, NuGet BuildTools, or PATH"
        );
        return ExitCode::FAILURE;
    };

    let res_path = out_dir.join("explorer_ext.res");
    let status = Command::new(&rc_exe)
        .arg("/nologo")
        .arg("/I")
        .arg(&assets_dir)
        .arg("/fo")
        .arg(&res_path)
        .arg(&rc_script)
        .status();

    match status {
        Ok(exit) if exit.success() => {
            if !res_path.is_file() {
                println!(
                    "cargo::error=rc.exe succeeded but did not produce {}",
                    res_path.display()
                );
                return ExitCode::FAILURE;
            }
            println!("cargo::rustc-link-arg-cdylib={}", res_path.display());
            ExitCode::SUCCESS
        }
        Ok(exit) => {
            println!(
                "cargo::error=rc.exe ({}) failed with status {exit}",
                rc_exe.display()
            );
            ExitCode::FAILURE
        }
        Err(err) => {
            println!(
                "cargo::error=failed to invoke rc.exe ({}): {err}",
                rc_exe.display()
            );
            ExitCode::FAILURE
        }
    }
}

fn host_arch_candidates() -> [&'static str; 2] {
    if cfg!(target_arch = "aarch64") {
        ["arm64", "x64"]
    } else {
        ["x64", "arm64"]
    }
}

fn parse_four_part_version(name: &str) -> Option<[u32; 4]> {
    let mut iter = name.split('.');
    let a = iter.next()?.parse::<u32>().ok()?;
    let b = iter.next()?.parse::<u32>().ok()?;
    let c = iter.next()?.parse::<u32>().ok()?;
    let d = iter.next()?.parse::<u32>().ok()?;
    if iter.next().is_some() {
        return None;
    }
    Some([a, b, c, d])
}

fn find_rc_under_versioned_bin(bin_root: &Path, arches: &[&str]) -> Option<PathBuf> {
    let entries = fs::read_dir(bin_root).ok()?;
    let mut versions: Vec<([u32; 4], PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if let Some(name) = path.file_name().and_then(|n| n.to_str())
            && let Some(parsed) = parse_four_part_version(name)
        {
            versions.push((parsed, path));
        }
    }
    versions.sort_by_key(|entry| std::cmp::Reverse(entry.0));
    for (_, ver_dir) in versions {
        for arch in arches {
            let candidate = ver_dir.join(arch).join("rc.exe");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn locate_rc_exe() -> Option<PathBuf> {
    let arches = host_arch_candidates();

    // 1. Explicit WindowsSdkDir + WindowsSDKVersion environment variables.
    if let Ok(sdk_dir) = env::var("WindowsSdkDir") {
        let sdk_path = PathBuf::from(&sdk_dir);
        if let Ok(sdk_ver) = env::var("WindowsSDKVersion") {
            let trimmed = sdk_ver.trim().trim_end_matches(['\\', '/']);
            if !trimmed.is_empty() {
                for arch in arches {
                    let candidate = sdk_path.join("bin").join(trimmed).join(arch).join("rc.exe");
                    if candidate.is_file() {
                        return Some(candidate);
                    }
                }
            }
        }
        if let Some(found) = find_rc_under_versioned_bin(&sdk_path.join("bin"), &arches) {
            return Some(found);
        }
    }

    // 2. Installed Windows Kits 10 under ProgramFiles(x86) / ProgramFiles.
    for env_key in ["ProgramFiles(x86)", "ProgramFiles"] {
        if let Ok(pf) = env::var(env_key) {
            let kits_bin = PathBuf::from(pf)
                .join("Windows Kits")
                .join("10")
                .join("bin");
            if let Some(found) = find_rc_under_versioned_bin(&kits_bin, &arches) {
                return Some(found);
            }
        }
    }

    // 3. Restored NuGet Microsoft.Windows.SDK.BuildTools package cache.
    let nuget_root = env::var("NUGET_PACKAGES")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            env::var("USERPROFILE")
                .ok()
                .map(|p| PathBuf::from(p).join(".nuget").join("packages"))
        });
    if let Some(root) = nuget_root {
        let bt_dir = root.join("microsoft.windows.sdk.buildtools");
        if let Ok(entries) = fs::read_dir(bt_dir) {
            let mut pkg_dirs: Vec<(Option<[u32; 4]>, PathBuf)> = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .map(|p| {
                    let ver = p
                        .file_name()
                        .and_then(|n| n.to_str())
                        .and_then(parse_four_part_version);
                    (ver, p)
                })
                .collect();
            pkg_dirs.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
            for (_, pkg) in pkg_dirs {
                if let Some(found) = find_rc_under_versioned_bin(&pkg.join("bin"), &arches) {
                    return Some(found);
                }
            }
        }
    }

    // 4. Ambient PATH fallback.
    if let Ok(path_env) = env::var("PATH") {
        for dir in env::split_paths(&path_env) {
            let candidate = dir.join("rc.exe");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    None
}
