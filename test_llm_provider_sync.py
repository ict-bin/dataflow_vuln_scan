import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from app.service import llm_provider_sync


class _FakeResponse:
    def __init__(self, payload: dict, status_code: int = 200):
        self._payload = payload
        self.status_code = status_code

    def json(self) -> dict:
        return self._payload


def _provider_payload() -> dict:
    return {
        "items": [
            {
                "enabled": True,
                "provider_key": "local-glm",
                "provider_type": "openai",
                "api_base": "http://example/v1",
                "api_key": "secret",
                "model": "glm-5.2",
            }
        ]
    }


def _thinking_config(mode: str) -> dict:
    payload = {
        "pi_thinking_format": mode,
        "pi_chat_template_kwargs": {
            "thinking": {
                "$var": "thinking.enabled",
            }
        },
        "pi_supports_reasoning_effort": False,
    }
    if mode == "together":
        payload["pi_supports_reasoning_effort"] = True
    return payload


class LlmProviderSyncTests(unittest.TestCase):
    def test_build_models_json_defaults_to_qwen_chat_template(self):
        providers = [
            {
                "enabled": True,
                "provider_key": "local-glm",
                "provider_type": "openai",
                "api_base": "http://example/v1",
                "api_key": "secret",
                "model": "glm-5.2",
            }
        ]

        models_json = llm_provider_sync.build_models_json(providers)

        model_entry = models_json["providers"]["local-glm"]["models"][0]
        self.assertTrue(model_entry["reasoning"])
        self.assertEqual("qwen-chat-template", model_entry["compat"]["thinkingFormat"])
        self.assertFalse(model_entry["compat"]["supportsDeveloperRole"])
        self.assertNotIn("chatTemplateKwargs", model_entry["compat"])

    def test_sync_providers_to_pi_loads_thinking_config_from_db(self):
        provider_payload = _provider_payload()
        db = Mock()

        with tempfile.TemporaryDirectory() as pi_dir:
            models_path = Path(pi_dir) / "models.json"
            fake_config_service = Mock()
            fake_config_service.get_config.return_value = _thinking_config("openrouter")
            with patch.dict(llm_provider_sync.os.environ, {"PI_CODING_AGENT_DIR": pi_dir}, clear=False):
                with patch.object(llm_provider_sync, "_PI_DIR", pi_dir):
                    with patch.object(llm_provider_sync.httpx, "get", return_value=_FakeResponse(provider_payload)):
                        with patch.object(llm_provider_sync, "_fetch_gateway_model_aliases", return_value=[]):
                            with patch("app.service.config_service.get_config_service", return_value=fake_config_service):
                                ok = llm_provider_sync.sync_providers_to_pi("http://config-center", db=db)

            self.assertTrue(ok)
            fake_config_service.get_config.assert_called_once_with(db)
            written = json.loads(models_path.read_text(encoding="utf-8"))
            self.assertEqual(
                "openrouter",
                written["providers"]["local-glm"]["models"][0]["compat"]["thinkingFormat"],
            )

    def test_sync_providers_to_pi_writes_expected_compat_for_each_thinking_format(self):
        provider_payload = _provider_payload()
        expectations = {
            "reasoning_effort": {
                "thinkingFormat": "reasoning_effort",
            },
            "openrouter": {
                "thinkingFormat": "openrouter",
            },
            "deepseek": {
                "thinkingFormat": "deepseek",
            },
            "together": {
                "thinkingFormat": "together",
                "supportsReasoningEffort": True,
            },
            "zai": {
                "thinkingFormat": "zai",
            },
            "qwen": {
                "thinkingFormat": "qwen",
            },
            "chat-template": {
                "thinkingFormat": "chat-template",
                "chatTemplateKwargs": {
                    "thinking": {
                        "$var": "thinking.enabled",
                    }
                },
            },
            "qwen-chat-template": {
                "thinkingFormat": "qwen-chat-template",
            },
        }

        for mode, expected in expectations.items():
            with self.subTest(mode=mode):
                with tempfile.TemporaryDirectory() as pi_dir:
                    models_path = Path(pi_dir) / "models.json"
                    with patch.dict(llm_provider_sync.os.environ, {"PI_CODING_AGENT_DIR": pi_dir}, clear=False):
                        with patch.object(llm_provider_sync, "_PI_DIR", pi_dir):
                            with patch.object(llm_provider_sync.httpx, "get", return_value=_FakeResponse(provider_payload)):
                                with patch.object(llm_provider_sync, "_fetch_gateway_model_aliases", return_value=[]):
                                    with patch.object(
                                        llm_provider_sync,
                                        "_load_runtime_thinking_config",
                                        return_value=_thinking_config(mode),
                                    ):
                                        ok = llm_provider_sync.sync_providers_to_pi("http://config-center")

                    self.assertTrue(ok)
                    written = json.loads(models_path.read_text(encoding="utf-8"))
                    model_entry = written["providers"]["local-glm"]["models"][0]
                    compat = model_entry["compat"]
                    self.assertTrue(model_entry["reasoning"])
                    self.assertEqual(expected["thinkingFormat"], compat["thinkingFormat"])
                    self.assertFalse(compat["supportsDeveloperRole"])
                    if "supportsReasoningEffort" in expected:
                        self.assertEqual(expected["supportsReasoningEffort"], compat["supportsReasoningEffort"])
                    else:
                        self.assertNotIn("supportsReasoningEffort", compat)
                    if "chatTemplateKwargs" in expected:
                        self.assertEqual(expected["chatTemplateKwargs"], compat["chatTemplateKwargs"])
                    else:
                        self.assertNotIn("chatTemplateKwargs", compat)

    def test_gateway_alias_models_inherit_runtime_thinking_config(self):
        providers = [
            {
                "enabled": True,
                "provider_key": "gaiasec",
                "provider_type": "openai",
                "api_base": "http://example/v1",
                "api_key": "secret",
                "model": "auto",
            }
        ]
        aliases = [
            {
                "enabled": True,
                "alias_name": "auto",
                "max_tokens_default": 262144,
            }
        ]

        models_json = llm_provider_sync.build_models_json(
            providers,
            gateway_model_aliases=aliases,
            thinking_config=_thinking_config("chat-template"),
        )

        model_entry = models_json["providers"]["gaiasec"]["models"][0]
        self.assertEqual("chat-template", model_entry["compat"]["thinkingFormat"])
        self.assertEqual(
            {"thinking": {"$var": "thinking.enabled"}},
            model_entry["compat"]["chatTemplateKwargs"],
        )


if __name__ == "__main__":
    unittest.main()
