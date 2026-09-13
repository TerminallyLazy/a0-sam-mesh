import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ObservatoryTests(unittest.TestCase):
    def test_views_escape_remote_data_and_have_accessible_controls(self):
        page = (ROOT / "webui/observatory.html").read_text()
        for name in ("Node", "Catalog", "Routes", "Activity", "Embassy"):
            self.assertIn(">" + name + "<", page)
        self.assertIn("Emergency disconnect", page)
        self.assertIn('role="tablist"', page)
        self.assertNotIn("x-html", page)
        self.assertIn("x-text", page)

    def test_each_api_keeps_host_auth_csrf_and_sanitized_errors(self):
        for name in (
            "status",
            "catalog",
            "preflight",
            "approve",
            "revoke",
            "audit",
            "emergency_disconnect",
            "publication_start",
            "publication_status",
            "publication_close",
        ):
            tree = ast.parse((ROOT / "api" / (name + ".py")).read_text())
            classes = [n for n in tree.body if isinstance(n, ast.ClassDef)]
            self.assertEqual(len(classes), 1)
            self.assertIn("ApiHandler", ast.unparse(classes[0].bases[0]))
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.assertNotIn(node.name, ("requires_auth", "requires_csrf"))

    def test_native_component_mounts_and_settings_context(self):
        page = (ROOT / "webui/observatory.html").read_text()
        self.assertIn('x-destroy="s.cleanup()"', page)
        config = (ROOT / "webui/config.html").read_text()
        self.assertIn("$store.samSettings", config)
        self.assertIn("context.samMesh.openObservatory()", config)
        self.assertNotIn("globalThis.openSamObservatory", config)
        for extension in (ROOT / "extensions/webui").glob("*/*.html"):
            self.assertIn("x-data", extension.read_text())
        self.assertTrue((ROOT / "webui/main.html").is_file())
