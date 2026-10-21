from __future__ import annotations

import unittest
from dataclasses import replace
from unittest.mock import patch

from kryptscan.app import main


VALID_HASH = "a" * 64


class EndpointAgentReleaseTests(unittest.TestCase):
    def release_settings(self, **overrides):
        defaults = {
            "app_env": "staging",
            "kryptguard_agent_release_ready": True,
            "kryptguard_agent_allow_unsigned_testing": True,
            "kryptguard_agent_signed": False,
            "kryptguard_agent_setup_url": "https://downloads.example.test/KryptNetAgentSetup.exe",
            "kryptguard_agent_setup_sha256": VALID_HASH,
            "kryptguard_agent_msi_url": "https://downloads.example.test/KryptNetAgent.msi",
            "kryptguard_agent_msi_sha256": VALID_HASH,
        }
        defaults.update(overrides)
        return replace(main.settings, **defaults)

    def test_controlled_testing_release_is_available_only_outside_production(self):
        with patch.object(main, "settings", self.release_settings()):
            release = main._endpoint_agent_release()

        self.assertTrue(release["available"])
        self.assertEqual("controlled_testing", release["release_status"])
        self.assertEqual("/api/endpoint-agent/download/setup", release["packages"]["setup"]["download_url"])

    def test_invalid_setup_hash_holds_release(self):
        with patch.object(
            main,
            "settings",
            self.release_settings(kryptguard_agent_setup_sha256="invalid"),
        ):
            release = main._endpoint_agent_release()

        self.assertFalse(release["available"])
        self.assertIsNone(release["packages"]["setup"]["download_url"])

    def test_production_rejects_unsigned_release(self):
        production = self.release_settings(
            app_env="production",
            app_secret="production-secret-value",
            kryptnet_payment_webhook_secret="webhook-secret",
            payment_demo_mode=False,
            kryptguard_agent_allow_unsigned_testing=False,
        )
        with patch.object(main, "settings", production):
            with self.assertRaisesRegex(RuntimeError, "KRYPTGUARD_AGENT_SIGNED"):
                main._assert_secure_config()

    def test_production_rejects_missing_setup_package(self):
        production = self.release_settings(
            app_env="production",
            app_secret="production-secret-value",
            kryptnet_payment_webhook_secret="webhook-secret",
            payment_demo_mode=False,
            kryptguard_agent_allow_unsigned_testing=False,
            kryptguard_agent_signed=True,
            kryptguard_agent_setup_url="",
        )
        with patch.object(main, "settings", production):
            with self.assertRaisesRegex(RuntimeError, "KRYPTGUARD_AGENT_SETUP_URL"):
                main._assert_secure_config()


if __name__ == "__main__":
    unittest.main()
