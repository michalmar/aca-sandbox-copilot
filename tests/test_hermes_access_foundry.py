"""Focused contract for the image-managed Foundry request profile."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "hermes/image"))
import patch_upstream


class FoundryProfileTests(unittest.TestCase):
    def profile(self):
        class Captured(Exception):
            pass

        class BaseProfile:
            def build_api_kwargs_extras(self, *, reasoning_config=None, **context):
                return {"unchanged": True}, {"original_config": reasoning_config}

        class Capture:
            def replace(self, name, old, new):
                if name != "plugins/model-providers/azure-foundry/__init__.py":
                    raise AssertionError("Only the Foundry source patch should execute.")
                self.source = (old + ")").replace(old, new)
                raise Captured()

        captured = Capture()
        with patch.object(patch_upstream, "Patcher", return_value=captured), self.assertRaises(Captured):
            patch_upstream.patch(ROOT, ROOT)
        namespace = {"ProviderProfile": BaseProfile}
        exec(compile(captured.source, "<managed-foundry-profile>", "exec"), namespace)
        return namespace["azure_foundry"]

    def test_tool_enabled_deployment_pins_no_reasoning(self):
        profile = self.profile()
        for config in (None, {"enabled": False}, {"enabled": True, "effort": "high"}):
            with self.subTest(config=config):
                self.assertEqual(profile.build_api_kwargs_extras(
                    model="gpt-6-sol", reasoning_config=config, supports_reasoning=True,
                ), ({}, {"reasoning_effort": "none"}))

    def test_other_models_keep_the_original_provider_contract(self):
        profile = self.profile()
        config = {"enabled": True, "effort": "medium"}
        for model in (None, "", "gpt-6-sol-other", "gpt-4.1"):
            with self.subTest(model=model):
                self.assertEqual(profile.build_api_kwargs_extras(model=model, reasoning_config=config),
                                 ({"unchanged": True}, {"original_config": config}))


if __name__ == "__main__":
    unittest.main()
