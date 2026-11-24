// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later

using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using TotalDrop.WinUI.Interop;

namespace TotalDrop.WinUI.Tests;

internal static class FfiResolver
{
    private static int _registered;

    [ModuleInitializer]
    internal static void Register()
    {
        if (Interlocked.Exchange(ref _registered, 1) != 0)
        {
            return;
        }

        NativeLibrary.SetDllImportResolver(typeof(NativeBridge).Assembly, ResolveNativeLibrary);
    }

    private static nint ResolveNativeLibrary(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (!string.Equals(libraryName, "totaldrop_windows_ffi", StringComparison.OrdinalIgnoreCase))
        {
            return 0;
        }

        string? overridePath = Environment.GetEnvironmentVariable("TOTALDROP_FFI_DLL_PATH");
        if (!string.IsNullOrWhiteSpace(overridePath))
        {
            string trimmed = overridePath.Trim();
            string resolved = Path.GetFullPath(trimmed);
            if (!File.Exists(resolved))
            {
                string hint = Path.IsPathFullyQualified(trimmed)
                    ? string.Empty
                    : $" (TOTALDROP_FFI_DLL_PATH was relative; testhost CWD is '{Environment.CurrentDirectory}'. Pass an absolute path.)";
                throw new DllNotFoundException(
                    $"TOTALDROP_FFI_DLL_PATH is set to '{trimmed}' (resolved to '{resolved}'), but the file does not exist.{hint}");
            }

            return NativeLibrary.Load(resolved);
        }

        string fileName = OperatingSystem.IsWindows()
            ? "totaldrop_windows_ffi.dll"
            : OperatingSystem.IsMacOS()
                ? "libtotaldrop_windows_ffi.dylib"
                : "libtotaldrop_windows_ffi.so";

        string baseDir = AppContext.BaseDirectory;
        string repoRoot = FindRepoRoot(baseDir);

        string[] archTargets = RuntimeInformation.ProcessArchitecture == Architecture.Arm64
            ? ["aarch64-pc-windows-msvc", "x86_64-pc-windows-msvc"]
            : ["x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"];

#if DEBUG
        string[] candidates =
        [
            Path.Combine(baseDir, fileName),
            Path.Combine(repoRoot, "target", "debug", fileName),
            Path.Combine(repoRoot, "target", archTargets[0], "debug", fileName),
            Path.Combine(repoRoot, "target", archTargets[1], "debug", fileName),
            Path.Combine(repoRoot, "target", archTargets[0], "release", fileName),
            Path.Combine(repoRoot, "target", archTargets[1], "release", fileName),
            Path.Combine(repoRoot, "target", "release", fileName),
        ];
#else
        string[] candidates =
        [
            Path.Combine(baseDir, fileName),
            Path.Combine(repoRoot, "target", archTargets[0], "release", fileName),
            Path.Combine(repoRoot, "target", archTargets[1], "release", fileName),
            Path.Combine(repoRoot, "target", "release", fileName),
            Path.Combine(repoRoot, "target", "debug", fileName),
        ];
#endif

        foreach (string candidate in candidates)
        {
            if (File.Exists(candidate) && NativeLibrary.TryLoad(candidate, out nint handle))
            {
                return handle;
            }
        }

        return NativeLibrary.TryLoad(libraryName, assembly, searchPath, out nint fallback)
            ? fallback
            : 0;
    }

    internal static string FindRepoRoot(string startDir)
    {
        DirectoryInfo? dir = new(startDir);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "Cargo.toml"))
                && Directory.Exists(Path.Combine(dir.FullName, "ui-winui3-fluent2")))
            {
                return dir.FullName;
            }

            dir = dir.Parent;
        }

        return startDir;
    }
}
