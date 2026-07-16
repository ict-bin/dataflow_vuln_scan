import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.service import llm_provider_sync


class _FakeResponse:
    def __init__(self, payload: dict, status_code: int = 200):
        self._payload = payload
        self.status_code = status_code

    def json(self) -> dict:
        return self._payload


class LlmProviderSyncTests(unittest.TestCase):
    def test_build_models_json_sets_qwen_thinking_format_for_provider_models(self):
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
        self.assertEqual("qwen", model_entry["compat"]["thinkingFormat"])

    def test_sync_providers_to_pi_writes_qwen_thinking_format_to_models_json(self):
        provider_payload = {
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

        with tempfile.TemporaryDirectory() as pi_dir:
            models_path = Path(pi_dir) / "models.json"
            with patch.dict(llm_provider_sync.os.environ, {"PI_CODING_AGENT_DIR": pi_dir}, clear=False):
                with patch.object(llm_provider_sync, "_PI_DIR", pi_dir):
                    with patch.object(llm_provider_sync.httpx, "get", return_value=_FakeResponse(provider_payload)):
                        with patch.object(llm_provider_sync, "_fetch_gateway_model_aliases", return_value=[]):
                            ok = llm_provider_sync.sync_providers_to_pi("http://config-center")

            self.assertTrue(ok)
            written = json.loads(models_path.read_text(encoding="utf-8"))
            model_entry = written["providers"]["local-glm"]["models"][0]
            self.assertTrue(model_entry["reasoning"])
            self.assertEqual("qwen", model_entry["compat"]["thinkingFormat"])


if __name__ == "__main__":
    unittest.main()
