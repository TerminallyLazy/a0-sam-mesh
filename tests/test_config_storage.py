"""Generic host config hooks must reject secrets before JSON persistence or response."""

import copy
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml


class ConfigStorageTests(unittest.TestCase):
    def setUp(self):
        self.raw = yaml.safe_load((Path(__file__).parents[1] / "default_config.yaml").read_text())

    def test_raw_credential_is_rejected_with_sanitized_error(self):
        from helpers.config import validate_storage_config

        self.raw["transport"]["token"] = "private-credential-sentinel"
        with self.assertRaisesRegex(ValueError, "^invalid_sam_config$"):
            validate_storage_config(self.raw)

    def test_secret_reference_is_validated_without_reading_the_secret(self):
        from helpers.config import validate_storage_config

        self.raw["transport"]["token_secret_name"] = "SAM_NODE_TOKEN"
        with patch(
            "helpers.config._resolve_secret_name", side_effect=AssertionError("secret read")
        ):
            self.assertEqual(validate_storage_config(self.raw), self.raw)

    def test_invalid_schema_scope_and_secret_names_cannot_be_saved(self):
        from helpers.config import validate_storage_config

        for change in ("token_name", "unknown", "schema"):
            raw = copy.deepcopy(self.raw)
            if change == "token_name":
                raw["transport"]["token_secret_name"] = "secret value"
            elif change == "unknown":
                raw["private-data-as-key"] = "secret"
            else:
                raw["schema"] = "wrong"
            with self.assertRaisesRegex(ValueError, "^invalid_sam_config$"):
                validate_storage_config(raw)
