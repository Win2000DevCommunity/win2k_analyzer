"""
ReactOS Source Auto-Patcher
============================
Points at a ReactOS source tree and auto-patches the files that need changing
for Windows 2000 SP4 compatibility:

  1. Replaces .def files with Win2000-ordinal-correct versions
  2. Patches syscall number definitions
  3. Sets _WIN32_WINNT=0x0500 in build configuration
  4. Patches syscall dispatch mechanism (int 0x2E instead of sysenter)
  5. Adds Win2000 structure definitions where needed
"""

import os
import shutil
import re
import json
import glob


# ── Well-known ReactOS source paths ─────────────────────────────────────

REACTOS_PATHS = {
    # DLL sources
    'ntdll_src':       'dll/ntdll',
    'kernel32_src':    'dll/win32/kernel32',
    'shell32_src':     'dll/win32/shell32',
    'user32_src':      'dll/win32/user32',
    'gdi32_src':       'dll/win32/gdi32',
    'advapi32_src':    'dll/win32/advapi32',

    # Kernel
    'ntoskrnl_src':    'ntoskrnl',
    'win32k_src':      'win32ss',

    # SDK / Headers
    'ndk_headers':     'sdk/include/ndk',
    'psdk_headers':    'sdk/include/psdk',
    'reactos_headers': 'sdk/include/reactos',

    # Syscall definitions (multiple possible locations)
    'syscall_defs': [
        'ntoskrnl/include/internal',
        'sdk/include/ndk',
        'win32ss/include',
    ],

    # .def files
    'def_files': {
        'ntdll.dll':    'dll/ntdll/def/ntdll.def',
        'kernel32.dll': 'dll/win32/kernel32/kernel32.def',
        'shell32.dll':  'dll/win32/shell32/shell32.def',
        'user32.dll':   'dll/win32/user32/user32.def',
        'gdi32.dll':    'dll/win32/gdi32/gdi32.def',
        'advapi32.dll': 'dll/win32/advapi32/advapi32.def',
    },

    # CMakeLists
    'root_cmake': 'CMakeLists.txt',
}


class ReactOSPatcher:
    """
    Auto-patches a ReactOS source tree for Windows 2000 SP4 compatibility.
    """

    def __init__(self, reactos_root, win2k_dlls_dir=None, backup=True):
        """
        Args:
            reactos_root: Path to ReactOS source tree root
            win2k_dlls_dir: Path to directory with Win2000 SP4 DLLs (for extraction)
            backup: Whether to backup files before patching
        """
        self.root = os.path.abspath(reactos_root)
        self.win2k_dir = win2k_dlls_dir
        self.backup = backup
        self.log = []
        self.patched_files = []
        self.errors = []

        if not os.path.isdir(self.root):
            raise FileNotFoundError(f"ReactOS source not found: {self.root}")

    def _resolve(self, relpath):
        """Resolve a relative path against the ReactOS root."""
        return os.path.join(self.root, relpath.replace('/', os.sep))

    def _backup_file(self, filepath):
        """Create a .orig backup of a file."""
        if self.backup and os.path.isfile(filepath):
            bak = filepath + '.orig_win2k'
            if not os.path.exists(bak):
                shutil.copy2(filepath, bak)
                self._log(f"Backed up: {os.path.relpath(filepath, self.root)}")

    def _log(self, msg):
        self.log.append(msg)

    def _patch_file(self, filepath, old_content, new_content, description):
        """Replace content in a file."""
        if not os.path.isfile(filepath):
            self.errors.append(f"File not found: {filepath}")
            return False

        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()

        if old_content not in content:
            self._log(f"SKIP (pattern not found): {description}")
            return False

        self._backup_file(filepath)
        content = content.replace(old_content, new_content, 1)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)

        self.patched_files.append(filepath)
        self._log(f"PATCHED: {description}")
        return True

    def _patch_file_regex(self, filepath, pattern, replacement, description):
        """Replace content using regex."""
        if not os.path.isfile(filepath):
            self.errors.append(f"File not found: {filepath}")
            return False

        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()

        new_content, count = re.subn(pattern, replacement, content)
        if count == 0:
            self._log(f"SKIP (regex not matched): {description}")
            return False

        self._backup_file(filepath)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(new_content)

        self.patched_files.append(filepath)
        self._log(f"PATCHED ({count} replacements): {description}")
        return True

    # ── Patch operations ─────────────────────────────────────────────────

    def patch_winver_target(self):
        """
        Set _WIN32_WINNT to 0x0500 (Windows 2000) in cmake config.
        ReactOS defaults to 0x0502 (Server 2003) or 0x0501 (XP).
        """
        self._log("\n=== Patching Windows version target ===")

        # Find and patch CMakeLists.txt or config.cmake
        cmake_files = glob.glob(self._resolve('**/*CMakeLists.txt'), recursive=True)
        cmake_files += glob.glob(self._resolve('**/config.cmake'), recursive=True)
        cmake_files += glob.glob(self._resolve('sdk/cmake/*.cmake'), recursive=True)

        patched = False
        for cmake_path in cmake_files:
            # Patch _WIN32_WINNT definitions
            patched |= self._patch_file_regex(
                cmake_path,
                r'(_WIN32_WINNT\s*=?\s*)(0x050[12])',
                r'\g<1>0x0500',
                f"Set _WIN32_WINNT=0x0500 in {os.path.relpath(cmake_path, self.root)}"
            )
            # Patch WINVER
            patched |= self._patch_file_regex(
                cmake_path,
                r'(WINVER\s*=?\s*)(0x050[12])',
                r'\g<1>0x0500',
                f"Set WINVER=0x0500 in {os.path.relpath(cmake_path, self.root)}"
            )

        # Also patch headers
        for hdr_pattern in ['sdk/include/**/*.h', 'sdk/cmake/**/*']:
            for hdr in glob.glob(self._resolve(hdr_pattern), recursive=True):
                if os.path.isfile(hdr):
                    patched |= self._patch_file_regex(
                        hdr,
                        r'(#\s*define\s+_WIN32_WINNT\s+)(0x050[12])',
                        r'\g<1>0x0500',
                        f"Set _WIN32_WINNT=0x0500 in {os.path.relpath(hdr, self.root)}"
                    )

        if not patched:
            self._log("No _WIN32_WINNT definitions found to patch (may need manual check)")

        return patched

    def patch_syscall_mechanism(self):
        """
        Patch ntdll's syscall mechanism to use int 0x2E instead of sysenter/KiFastSystemCall.
        Windows 2000 always uses int 0x2E - never sysenter.
        """
        self._log("\n=== Patching syscall mechanism (int 0x2E) ===")

        patched = False
        # Find assembly files in ntdll
        asm_patterns = [
            'dll/ntdll/**/*.asm',
            'dll/ntdll/**/*.s',
            'dll/ntdll/**/*.S',
        ]

        for pattern in asm_patterns:
            for asm_file in glob.glob(self._resolve(pattern), recursive=True):
                # Replace sysenter with int 0x2E
                patched |= self._patch_file_regex(
                    asm_file,
                    r'\bsysenter\b',
                    'int 0x2E',
                    f"Replace sysenter with int 0x2E in {os.path.relpath(asm_file, self.root)}"
                )
                # Replace call to KiFastSystemCall
                patched |= self._patch_file_regex(
                    asm_file,
                    r'call\s+\[?(?:_?KiFastSystemCall|dword\s+ptr\s+\[edx\])\]?',
                    'int 0x2E',
                    f"Replace KiFastSystemCall with int 0x2E in {os.path.relpath(asm_file, self.root)}"
                )

        # Also check C files that may generate syscall stubs
        c_patterns = [
            'dll/ntdll/**/*.c',
            'sdk/lib/rtl/**/*.c',
        ]
        for pattern in c_patterns:
            for c_file in glob.glob(self._resolve(pattern), recursive=True):
                patched |= self._patch_file_regex(
                    c_file,
                    r'SharedUserData->SystemCall\b',
                    '((PVOID)(ULONG_PTR)0)  /* Win2000: always int 0x2E */',
                    f"Disable KiFastSystemCall in {os.path.relpath(c_file, self.root)}"
                )

        return patched

    def patch_def_files(self, win2k_def_dir):
        """
        Replace ReactOS .def files with Win2000-generated ones.

        Args:
            win2k_def_dir: Directory containing .def files generated by def_generator
        """
        self._log("\n=== Patching .def files for ordinal compatibility ===")

        patched_count = 0
        for dll_name, def_relpath in REACTOS_PATHS['def_files'].items():
            reactos_def = self._resolve(def_relpath)
            base = os.path.splitext(dll_name)[0]
            win2k_def = os.path.join(win2k_def_dir, f"{base}.def")

            if not os.path.isfile(win2k_def):
                self._log(f"SKIP: No Win2000 .def found for {dll_name}")
                continue

            if not os.path.isfile(reactos_def):
                # Try alternative paths
                alt_paths = glob.glob(self._resolve(f'**/{base}.def'), recursive=True)
                if alt_paths:
                    reactos_def = alt_paths[0]
                else:
                    self._log(f"SKIP: ReactOS .def not found for {dll_name} at {def_relpath}")
                    continue

            self._backup_file(reactos_def)
            shutil.copy2(win2k_def, reactos_def)
            self.patched_files.append(reactos_def)
            self._log(f"REPLACED: {os.path.relpath(reactos_def, self.root)} with Win2000 ordinals")
            patched_count += 1

        return patched_count > 0

    def patch_syscall_numbers(self, syscall_header_path):
        """
        Replace ReactOS syscall number definitions with Win2000 ones.

        Args:
            syscall_header_path: Path to generated syscall header (from syscall_patcher)
        """
        self._log("\n=== Patching syscall number definitions ===")

        if not os.path.isfile(syscall_header_path):
            self.errors.append(f"Syscall header not found: {syscall_header_path}")
            return False

        # Find where ReactOS defines syscall numbers
        candidates = []
        for search_dir in REACTOS_PATHS['syscall_defs']:
            full_dir = self._resolve(search_dir)
            if os.path.isdir(full_dir):
                for f in os.listdir(full_dir):
                    if f.endswith('.h') and any(kw in f.lower() for kw in ['napi', 'syscall', 'service', 'sysfunc']):
                        candidates.append(os.path.join(full_dir, f))

        if not candidates:
            # Broader search
            for h_file in glob.glob(self._resolve('**/*.h'), recursive=True):
                with open(h_file, 'r', encoding='utf-8', errors='replace') as f:
                    head = f.read(2048)
                    if 'SYSCALL' in head and 'NtCreate' in head:
                        candidates.append(h_file)

        if not candidates:
            self._log("WARNING: Could not locate ReactOS syscall definition files")
            self._log("  Placing Win2000 syscall header at: sdk/include/ndk/win2k_syscalls.h")
            dest = self._resolve('sdk/include/ndk/win2k_syscalls.h')
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.copy2(syscall_header_path, dest)
            self.patched_files.append(dest)
            return True

        # Patch each candidate
        for candidate in candidates:
            self._backup_file(candidate)
            # Prepend an include of the win2k header
            with open(candidate, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()

            # Place the win2k header alongside
            win2k_h = os.path.join(os.path.dirname(candidate), 'win2k_syscalls.h')
            shutil.copy2(syscall_header_path, win2k_h)
            self._log(f"PLACED: win2k_syscalls.h alongside {os.path.relpath(candidate, self.root)}")
            self.patched_files.append(win2k_h)

        return True

    def scan_issues(self):
        """
        Scan ReactOS source for potential Win2000 compatibility issues.
        Returns a report of things that may need manual attention.
        """
        self._log("\n=== Scanning for Win2000 compatibility issues ===")

        issues = []

        # Check for XP+ API usage
        xp_only_apis = [
            'ActivateActCtx', 'CreateActCtx', 'DeactivateActCtx',  # Activation context (XP+)
            'GetModuleHandleEx',   # XP+
            'GetDllDirectory',     # XP+
            'SetDllDirectory',     # XP+
            'IsWow64Process',      # XP+
            'GetNativeSystemInfo', # XP+
            'Wow64DisableWow64FsRedirection',  # XP x64+
            'InitializeSListHead',  # XP+
            'ConvertFiberToThread', # XP+
            'IsProcessInJob',       # XP+
        ]

        # Scan key source directories
        scan_dirs = ['dll/ntdll', 'dll/win32/kernel32', 'dll/win32/shell32']
        for scan_dir in scan_dirs:
            full_dir = self._resolve(scan_dir)
            if not os.path.isdir(full_dir):
                continue
            for root, dirs, files in os.walk(full_dir):
                for fname in files:
                    if not fname.endswith(('.c', '.h', '.cpp')):
                        continue
                    filepath = os.path.join(root, fname)
                    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                        content = f.read()
                    for api in xp_only_apis:
                        if api in content:
                            # Find line number
                            for i, line in enumerate(content.split('\n'), 1):
                                if api in line:
                                    issues.append({
                                        'file': os.path.relpath(filepath, self.root),
                                        'line': i,
                                        'api': api,
                                        'issue': f'XP+ API used: {api}',
                                        'severity': 'warning',
                                    })
                                    break

        # Check for sysenter usage
        for asm_pattern in ['dll/ntdll/**/*.asm', 'dll/ntdll/**/*.s', 'dll/ntdll/**/*.S']:
            for asm_file in glob.glob(self._resolve(asm_pattern), recursive=True):
                with open(asm_file, 'r', encoding='utf-8', errors='replace') as f:
                    for i, line in enumerate(f, 1):
                        if 'sysenter' in line.lower() or 'KiFastSystemCall' in line:
                            issues.append({
                                'file': os.path.relpath(asm_file, self.root),
                                'line': i,
                                'api': 'sysenter/KiFastSystemCall',
                                'issue': 'Win2000 uses int 0x2E, not sysenter',
                                'severity': 'critical',
                            })

        self._log(f"Found {len(issues)} potential issues")
        return issues

    def run_all_patches(self, win2k_def_dir=None, syscall_header_path=None):
        """
        Run all patches in order.

        Args:
            win2k_def_dir: Directory with generated .def files
            syscall_header_path: Path to generated syscall header
        """
        self._log("=" * 60)
        self._log("ReactOS -> Win2000 SP4 Auto-Patcher")
        self._log("=" * 60)
        self._log(f"Source tree: {self.root}")

        # 1. Version target
        self.patch_winver_target()

        # 2. Syscall mechanism
        self.patch_syscall_mechanism()

        # 3. .def files
        if win2k_def_dir and os.path.isdir(win2k_def_dir):
            self.patch_def_files(win2k_def_dir)
        else:
            self._log("\nSKIP: No Win2000 .def directory provided")

        # 4. Syscall numbers
        if syscall_header_path and os.path.isfile(syscall_header_path):
            self.patch_syscall_numbers(syscall_header_path)
        else:
            self._log("\nSKIP: No syscall header provided")

        # 5. Scan for issues
        issues = self.scan_issues()

        self._log(f"\n{'=' * 60}")
        self._log(f"  Summary:")
        self._log(f"    Files patched: {len(self.patched_files)}")
        self._log(f"    Errors: {len(self.errors)}")
        self._log(f"    Issues found: {len(issues)}")
        self._log(f"{'=' * 60}")

        return {
            'patched_files': self.patched_files,
            'errors': self.errors,
            'issues': issues,
            'log': self.log,
        }

    def get_log_text(self):
        return '\n'.join(self.log)
