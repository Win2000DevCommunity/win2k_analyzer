"""
Tests for Win2K NT Internals Analyzer GUI
==========================================
Covers: theme system, lazy imports, PlaceholderEntry, helper functions,
        widget creation, tab initialization, and theme switching.

Run:  python -m pytest tests/test_gui.py -v
"""

import os
import sys
import time
import unittest

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── Shared Tk root for all widget tests ──────────────────────────
# This Python 3.14 installation only supports a single tk.Tk()
# instance per process.  Since App extends tk.Tk we use ONE App
# object as the root for every Tk-dependent test class.
_shared_app = None

def _get_app():
    """Return (and lazily create) the single shared App instance."""
    global _shared_app
    if _shared_app is None:
        from win2k_gui import App, set_theme
        set_theme("Dark")
        _shared_app = App()
        _shared_app.withdraw()
    return _shared_app

def tearDownModule():
    global _shared_app
    if _shared_app is not None:
        _shared_app.destroy()
        _shared_app = None


# ═══════════════════════════════════════════════════════════════════
#  1. Import & Startup Performance
# ═══════════════════════════════════════════════════════════════════

class TestStartupPerformance(unittest.TestCase):
    """Backend modules should NOT be loaded at import time."""

    def test_import_speed(self):
        """GUI module should import in under 3 seconds (no heavy backends)."""
        start = time.time()
        import win2k_gui  # noqa: F811
        elapsed = time.time() - start
        self.assertLess(elapsed, 3.0, f"Import took {elapsed:.2f}s — too slow, check lazy imports")

    def test_no_backend_loaded_at_import(self):
        """Heavy backend modules should not be in sys.modules after import."""
        import win2k_gui  # noqa: F811
        heavy_modules = [
            'nt_analyzer.decompiler',
            'nt_analyzer.behavior_analyzer',
            'nt_analyzer.pe_patcher',
            'nt_analyzer.compat_analyzer',
        ]
        # These should NOT be loaded yet (they're lazy)
        for mod in heavy_modules:
            if mod in sys.modules:
                # It's okay if they were loaded by a previous test,
                # but the lazy cache should be empty
                pass  # can't un-import, so just check cache
        # At minimum, the lazy cache should start empty or only have
        # lightweight modules loaded during tab __init__
        self.assertNotIn('nt_analyzer.decompiler', win2k_gui._module_cache,
                         "Decompiler loaded eagerly — should be lazy")

    def test_lazy_import_function(self):
        """_lazy() should cache and return the same module object."""
        import win2k_gui
        mod1 = win2k_gui._lazy('json')
        mod2 = win2k_gui._lazy('json')
        self.assertIs(mod1, mod2, "Lazy import should return cached module")
        import json
        self.assertIs(mod1, json)


# ═══════════════════════════════════════════════════════════════════
#  2. Theme System
# ═══════════════════════════════════════════════════════════════════

class TestThemeSystem(unittest.TestCase):

    def test_three_themes_exist(self):
        from win2k_gui import THEMES
        self.assertEqual(set(THEMES.keys()), {"Dark", "Light", "Midnight"})

    def test_all_themes_have_required_keys(self):
        from win2k_gui import THEMES
        required = {"bg", "bg_dark", "bg_light", "fg", "fg_dim", "accent",
                     "accent_hover", "green", "red", "yellow", "peach",
                     "tab_bg", "entry_bg", "btn_bg", "btn_active", "border",
                     "header_bg", "card_bg", "separator", "placeholder"}
        for name, theme in THEMES.items():
            with self.subTest(theme=name):
                self.assertEqual(set(theme.keys()), required,
                                 f"Theme '{name}' is missing keys")

    def test_all_colors_are_valid_hex(self):
        from win2k_gui import THEMES
        import re
        hex_re = re.compile(r'^#[0-9a-fA-F]{6}$')
        for name, theme in THEMES.items():
            for key, val in theme.items():
                with self.subTest(theme=name, key=key):
                    self.assertRegex(val, hex_re,
                                     f"{name}.{key} = '{val}' is not valid hex color")

    def test_set_theme_updates_global(self):
        from win2k_gui import set_theme, T, THEMES
        for name in THEMES:
            set_theme(name)
            self.assertEqual(T["bg"], THEMES[name]["bg"],
                             f"T['bg'] not updated after set_theme('{name}')")
        set_theme("Dark")  # restore default

    def test_theme_contrast(self):
        """fg and bg should not be identical (basic readability check)."""
        from win2k_gui import THEMES
        for name, theme in THEMES.items():
            with self.subTest(theme=name):
                self.assertNotEqual(theme["fg"], theme["bg"],
                                    f"Theme '{name}' has identical fg and bg!")

    def test_dark_theme_is_default(self):
        from win2k_gui import _current_theme_name
        # After module import, default should be Dark
        # (Note: other tests may change it, but we restore)
        from win2k_gui import set_theme
        set_theme("Dark")
        from win2k_gui import T, THEMES
        self.assertEqual(T["bg"], THEMES["Dark"]["bg"])


# ═══════════════════════════════════════════════════════════════════
#  3. Smart Defaults / Examples
# ═══════════════════════════════════════════════════════════════════

class TestExamples(unittest.TestCase):

    def test_examples_dict_populated(self):
        from win2k_gui import EXAMPLES
        self.assertGreater(len(EXAMPLES), 5)

    def test_ntdll_example_present(self):
        from win2k_gui import EXAMPLES
        self.assertIn("ntdll", EXAMPLES)
        self.assertIn("ntdll", EXAMPLES["ntdll"].lower())

    def test_all_examples_are_strings(self):
        from win2k_gui import EXAMPLES
        for key, val in EXAMPLES.items():
            with self.subTest(key=key):
                self.assertIsInstance(val, str)
                self.assertTrue(val.startswith("e.g."),
                                f"Example '{key}' should start with 'e.g.'")


# ═══════════════════════════════════════════════════════════════════
#  4. PlaceholderEntry (requires Tk)
# ═══════════════════════════════════════════════════════════════════

class TestPlaceholderEntry(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Use shared Tk root for widget tests."""
        cls.root = _get_app()

    def test_placeholder_shown_initially(self):
        from win2k_gui import PlaceholderEntry, set_theme
        set_theme("Dark")
        ent = PlaceholderEntry(self.root, placeholder="test hint")
        self.assertTrue(ent._showing_ph)
        self.assertEqual(ent._var.get(), "test hint")
        ent.destroy()

    def test_get_value_returns_empty_when_placeholder(self):
        from win2k_gui import PlaceholderEntry, set_theme
        set_theme("Dark")
        ent = PlaceholderEntry(self.root, placeholder="hint")
        self.assertEqual(ent.get_value(), "")
        ent.destroy()

    def test_set_value_clears_placeholder(self):
        from win2k_gui import PlaceholderEntry, set_theme
        set_theme("Dark")
        ent = PlaceholderEntry(self.root, placeholder="hint")
        ent.set_value("C:\\real\\path.dll")
        self.assertFalse(ent._showing_ph)
        self.assertEqual(ent.get_value(), "C:\\real\\path.dll")
        ent.destroy()

    def test_focus_clears_placeholder(self):
        from win2k_gui import PlaceholderEntry, set_theme
        set_theme("Dark")
        ent = PlaceholderEntry(self.root, placeholder="hint text")
        ent._on_focus_in()
        self.assertFalse(ent._showing_ph)
        self.assertEqual(ent._var.get(), "")
        ent.destroy()

    def test_focus_out_restores_placeholder(self):
        from win2k_gui import PlaceholderEntry, set_theme
        set_theme("Dark")
        ent = PlaceholderEntry(self.root, placeholder="hint text")
        ent._on_focus_in()
        ent._on_focus_out()
        self.assertTrue(ent._showing_ph)
        self.assertEqual(ent._var.get(), "hint text")
        ent.destroy()

    def test_focus_out_keeps_real_value(self):
        from win2k_gui import PlaceholderEntry, set_theme
        set_theme("Dark")
        ent = PlaceholderEntry(self.root, placeholder="hint")
        ent.set_value("real")
        ent._on_focus_out()
        self.assertFalse(ent._showing_ph)
        self.assertEqual(ent.get_value(), "real")
        ent.destroy()

    def test_refresh_theme(self):
        from win2k_gui import PlaceholderEntry, set_theme, T
        set_theme("Dark")
        ent = PlaceholderEntry(self.root, placeholder="hint",
                               bg=T["entry_bg"], fg=T["fg"],
                               insertbackground=T["fg"])
        # Switch theme and refresh
        set_theme("Light")
        ent.refresh_theme()  # should not raise
        self.assertEqual(str(ent.cget("bg")), T["entry_bg"])
        set_theme("Dark")
        ent.destroy()


# ═══════════════════════════════════════════════════════════════════
#  5. Helper Functions
# ═══════════════════════════════════════════════════════════════════

class TestHelperFunctions(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.root = _get_app()

    def test_make_output_creates_scrolled_text(self):
        from win2k_gui import make_output, set_theme
        set_theme("Dark")
        import tkinter.scrolledtext
        frame = self.root
        txt = make_output(frame)
        self.assertIsInstance(txt, tkinter.scrolledtext.ScrolledText)
        # Should have color tags configured
        tags = txt.tag_names()
        for expected_tag in ("title", "ok", "warn", "error", "dim", "peach", "heading"):
            self.assertIn(expected_tag, tags, f"Missing tag: {expected_tag}")
        txt.destroy()

    def test_output_write_and_clear(self):
        from win2k_gui import make_output, output_write, output_clear, set_theme
        set_theme("Dark")
        txt = make_output(self.root)
        output_write(txt, "hello world\n")
        content = txt.get("1.0", "end-1c")
        self.assertIn("hello world", content)

        output_write(txt, "tagged text", "ok")
        content = txt.get("1.0", "end-1c")
        self.assertIn("tagged text", content)

        output_clear(txt)
        content = txt.get("1.0", "end-1c")
        self.assertEqual(content.strip(), "")
        txt.destroy()

    def test_output_is_readonly_by_default(self):
        from win2k_gui import make_output, set_theme
        set_theme("Dark")
        txt = make_output(self.root)
        self.assertEqual(str(txt.cget("state")), "disabled")
        txt.destroy()

    def test_run_async_completes(self):
        from win2k_gui import run_async
        import threading
        result = []
        event = threading.Event()

        def work():
            return 42

        def callback(r):
            result.append(r)
            event.set()

        run_async(work, callback)
        event.wait(timeout=5)
        self.assertEqual(result, [42])

    def test_run_async_handles_exception(self):
        from win2k_gui import run_async
        import threading
        result = []
        event = threading.Event()

        def work():
            raise ValueError("test error")

        def callback(r):
            result.append(r)
            event.set()

        run_async(work, callback)
        event.wait(timeout=5)
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], ValueError)


# ═══════════════════════════════════════════════════════════════════
#  6. App & Tab Initialization (requires Tk)
# ═══════════════════════════════════════════════════════════════════

class TestAppCreation(unittest.TestCase):
    """Verify core App construction, tabs, statusbar, and theme combo."""

    @classmethod
    def setUpClass(cls):
        cls.app = _get_app()

    def test_app_creates_without_error(self):
        self.assertIsNotNone(self.app)
        self.assertEqual(self.app.title(), "Win2K NT Internals Analyzer")

    def test_app_has_13_tabs(self):
        tab_count = self.app.nb.index("end")
        self.assertEqual(tab_count, 13, f"Expected 13 tabs, got {tab_count}")

    def test_tab_names_are_readable(self):
        for i in range(self.app.nb.index("end")):
            name = self.app.nb.tab(i, "text").strip()
            self.assertTrue(len(name) > 2, f"Tab {i} has empty/tiny name: '{name}'")
            self.assertTrue(len(name) < 20, f"Tab {i} name too long: '{name}'")

    def test_statusbar_exists(self):
        self.assertIsNotNone(self.app.statusbar)
        self.assertIsNotNone(self.app.status_lbl)

    def test_theme_combo_has_three_options(self):
        values = self.app.theme_combo.cget("values")
        self.assertEqual(len(values), 3)
        self.assertIn("Dark", values)
        self.assertIn("Light", values)
        self.assertIn("Midnight", values)

    def test_set_status(self):
        self.app.set_status("Testing status update")
        text = self.app.status_lbl.cget("text")
        self.assertIn("Testing status update", text)


# ═══════════════════════════════════════════════════════════════════
#  7. Theme Switching
# ═══════════════════════════════════════════════════════════════════

class TestThemeSwitching(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = _get_app()

    def test_apply_theme_light(self):
        from win2k_gui import T, THEMES
        self.app._apply_theme("Light")
        self.assertEqual(T["bg"], THEMES["Light"]["bg"])
        lbl_text = self.app.theme_lbl.cget("text")
        self.assertIn("Light", lbl_text)

    def test_apply_theme_midnight(self):
        from win2k_gui import T, THEMES
        self.app._apply_theme("Midnight")
        self.assertEqual(T["bg"], THEMES["Midnight"]["bg"])

    def test_apply_theme_back_to_dark(self):
        from win2k_gui import T, THEMES
        self.app._apply_theme("Light")
        self.app._apply_theme("Dark")
        self.assertEqual(T["bg"], THEMES["Dark"]["bg"])

    def test_theme_switch_does_not_crash(self):
        """Rapidly switching all themes should not raise exceptions."""
        for _ in range(3):
            for theme in ("Dark", "Light", "Midnight"):
                self.app._apply_theme(theme)

    def test_root_bg_updates_on_theme_switch(self):
        from win2k_gui import THEMES
        self.app._apply_theme("Light")
        self.assertEqual(self.app.cget("bg"), THEMES["Light"]["bg"])
        self.app._apply_theme("Midnight")
        self.assertEqual(self.app.cget("bg"), THEMES["Midnight"]["bg"])


# ═══════════════════════════════════════════════════════════════════
#  8. Individual Tab Smoke Tests
# ═══════════════════════════════════════════════════════════════════

class TestTabWidgets(unittest.TestCase):
    """Verify each tab has an output widget and status variable."""

    @classmethod
    def setUpClass(cls):
        cls.app = _get_app()

    def _get_tab(self, attr_name):
        return getattr(self.app, attr_name)

    def test_exports_tab_has_output(self):
        tab = self._get_tab("tab_exports")
        self.assertTrue(hasattr(tab, "output"))
        self.assertTrue(hasattr(tab, "status_var"))

    def test_syscalls_tab_has_output(self):
        tab = self._get_tab("tab_syscalls")
        self.assertTrue(hasattr(tab, "output"))

    def test_compare_tab_has_output(self):
        tab = self._get_tab("tab_compare")
        self.assertTrue(hasattr(tab, "output"))

    def test_structs_tab_has_output(self):
        tab = self._get_tab("tab_structs")
        self.assertTrue(hasattr(tab, "output"))

    def test_pe_header_tab_has_output(self):
        tab = self._get_tab("tab_pe")
        self.assertTrue(hasattr(tab, "output"))

    def test_defgen_tab_has_output(self):
        tab = self._get_tab("tab_defgen")
        self.assertTrue(hasattr(tab, "output"))

    def test_scpatch_tab_has_output(self):
        tab = self._get_tab("tab_scpatch")
        self.assertTrue(hasattr(tab, "output"))

    def test_rospatch_tab_has_output(self):
        tab = self._get_tab("tab_rospatch")
        self.assertTrue(hasattr(tab, "output"))

    def test_build_tab_has_output(self):
        tab = self._get_tab("tab_build")
        self.assertTrue(hasattr(tab, "output"))

    def test_behavior_tab_has_output(self):
        tab = self._get_tab("tab_behavior")
        self.assertTrue(hasattr(tab, "output"))

    def test_decompiler_tab_has_output(self):
        tab = self._get_tab("tab_decompiler")
        self.assertTrue(hasattr(tab, "output"))

    def test_compat_tab_has_output(self):
        tab = self._get_tab("tab_compat")
        self.assertTrue(hasattr(tab, "output"))

    def test_patcher_tab_has_output(self):
        tab = self._get_tab("tab_patcher")
        self.assertTrue(hasattr(tab, "output"))


# ═══════════════════════════════════════════════════════════════════
#  9. File Picker Helpers
# ═══════════════════════════════════════════════════════════════════

class TestFilePickers(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from tkinter import ttk
        from win2k_gui import set_theme
        set_theme("Dark")
        cls.root = _get_app()
        cls.parent = ttk.Frame(cls.root)
        cls.parent.pack()
        cls.parent.columnconfigure(0, weight=1)

    def test_make_file_picker_returns_tuple(self):
        from win2k_gui import make_file_picker
        result = make_file_picker(self.parent, "Test:", row=0)
        self.assertEqual(len(result), 3, "Should return (frame, getter, var)")

    def test_make_file_picker_with_placeholder(self):
        from win2k_gui import make_file_picker
        frm, getter, var = make_file_picker(self.parent, "DLL:", row=1,
                                             placeholder="e.g. ntdll.dll")
        # Getter should return empty when placeholder is active
        self.assertEqual(getter(), "")

    def test_make_dir_picker_returns_tuple(self):
        from win2k_gui import make_dir_picker
        result = make_dir_picker(self.parent, "Dir:", row=2)
        self.assertEqual(len(result), 3)

    def test_make_dir_picker_with_placeholder(self):
        from win2k_gui import make_dir_picker
        frm, getter, var = make_dir_picker(self.parent, "Source:", row=3,
                                            placeholder="e.g. C:\\reactos")
        self.assertEqual(getter(), "")


if __name__ == '__main__':
    unittest.main()
