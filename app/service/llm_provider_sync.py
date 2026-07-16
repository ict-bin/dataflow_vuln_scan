"""
llm_provider_sync.py — 从两个来源同步 LLM 模型信息，生成 pi 的 models.json

来源 1: 配置中心 /service/llm/providers (模型配置中心)
  - 直连 Provider (local_minimax, local_codex 等)
  - gaiasec Provider (网关入口, model=auto)

来源 2: AIGW MySQL gaiasec_llm_gateway.model_aliases (网关配置)
  - 网关可路由的模型别名 (auto, max, pro 等)
  - 合并到 gaiasec provider 的 models 列表
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger("dvs.llm_sync")

_PI_DIR = os.environ.get("PI_CODING_AGENT_DIR", "/root/.pi/agent")
_DEFAULT_CONTEXT_WINDOW = 128000


def _provider_api(provider_type: str) -> str:
    normalized = str(provider_type or "").strip().lower()
    if normalized == "anthropic":
        return "anthropic-messages"
    return "openai-completions"


def _as_positive_int(value: Any, default: int) -> int:
    try:
        parsed = int(value)
        return parsed if parsed > 0 else default
    except (TypeError, ValueError):
        return default


# context_window 下限: 低于 128K 的一律取 128K (防网关别名 max_tokens_default 等误配小值导致 LLM 输出被截断)
_MIN_CONTEXT_WINDOW = 128000
# max_output_tokens 下限: 最小 32K (防 pi 默认 16384 太小导致 JSON 截断)
_MIN_MAX_TOKENS = 32768


def _floor_context_window(cw: int) -> int:
    """context_window 下限保护: 低于 128K 取 128K."""
    return max(cw, _MIN_CONTEXT_WINDOW)


def _floor_max_tokens(mt: Any) -> int:
    """max_output_tokens 下限保护: 低于 32K 取 32K; None/无效取 32K."""
    try:
        v = int(mt)
        return max(v, _MIN_MAX_TOKENS) if v > 0 else _MIN_MAX_TOKENS
    except (TypeError, ValueError):
        return _MIN_MAX_TOKENS


def _apply_zai_reasoning_compat(entry: dict[str, Any]) -> None:
    """Keep existing model fields and mark reasoning-capable models."""
    entry["reasoning"] = True
    compat = dict(entry.get("compat") or {})
    compat["thinkingFormat"] = "qwen"
    compat["supportsDeveloperRole"] = False
    entry["compat"] = compat


def _model_entries(provider: dict[str, Any]) -> list[dict[str, Any]]:
    model_id = str(provider.get("model") or "").strip()
    extra_config = provider.get("extra_config") if isinstance(provider.get("extra_config"), dict) else {}
    context_window = _floor_context_window(_as_positive_int(
        provider.get("model_context_window")
        or provider.get("context_window")
        or provider.get("contextWindow")
        or provider.get("context_length")
        or provider.get("contextLength")
        or extra_config.get("model_context_window")
        or extra_config.get("contextWindow")
        or extra_config.get("context_length")
        or extra_config.get("contextLength"),
        _DEFAULT_CONTEXT_WINDOW,
    ))
    pi_models = extra_config.get("pi_models")
    raw_models = pi_models if isinstance(pi_models, list) else (
        [{"id": model_id}] if model_id else []
    )
    models: list[dict[str, Any]] = []
    for raw in raw_models:
        if not isinstance(raw, dict):
            continue
        entry = dict(raw)
        # max_output_tokens 下限 32K (不再 strip, 防 pi 默认 16384 太小截断 LLM 输出)
        _existing_mt = None
        for _k in list(entry.keys()):
            if _k.lower() in ("maxtokens", "max_tokens", "max_output_tokens", "maxoutputtokens"):
                _existing_mt = entry.pop(_k)
        entry["maxTokens"] = _floor_max_tokens(_existing_mt)
        entry.setdefault("id", model_id)
        entry.setdefault("name", entry.get("id") or model_id)
        entry.setdefault("input", ["text"])
        entry.setdefault("contextWindow", context_window)
        entry.setdefault("contextLength", context_window)
        entry.setdefault("cost", {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0})
        _apply_zai_reasoning_compat(entry)
        models.append(entry)
    return models


def build_models_json(providers: list[dict[str, Any]], gateway_model_aliases: list[dict[str, Any]] | None = None) -> dict:
    """
    将配置中心的 LlmProviderSummary 列表 + AIGW model_aliases 转换为 pi 的 models.json。
    
    gateway_model_aliases 中的别名会合并到 gaiasec provider 的 models 列表。
    """
    result: dict[str, Any] = {"providers": {}}
    for p in providers:
        if not p.get("enabled"):
            continue
        key = p.get("provider_key", "").strip()
        if not key:
            continue
        models = _model_entries(p)
        # Source 2: AIGW model aliases → 合并到 gaiasec provider
        if key == "gaiasec" and gateway_model_aliases:
            alias_models: list[dict[str, Any]] = []
            for a in gateway_model_aliases:
                if not a.get("enabled"):
                    continue
                alias_name = str(a.get("alias_name") or "").strip()
                if not alias_name:
                    continue
                alias_models.append({
                    "id": alias_name,
                    "name": alias_name,
                    "input": ["text"],
                    "contextWindow": _floor_context_window(_as_positive_int(a.get("max_tokens_default"), _DEFAULT_CONTEXT_WINDOW)),
                    "contextLength": _floor_context_window(_as_positive_int(a.get("max_tokens_default"), _DEFAULT_CONTEXT_WINDOW)),
                    "maxTokens": _floor_max_tokens(a.get("max_tokens_default")),
                    "cost": {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0},
                })
                _apply_zai_reasoning_compat(alias_models[-1])
            if alias_models:
                models = alias_models
        result["providers"][key] = {
            "baseUrl": p.get("api_base", ""),
            "api": _provider_api(str(p.get("provider_type") or "")),
            "apiKey": p.get("api_key", ""),
            "models": models,
        }
    return result


def _fetch_gateway_model_aliases() -> list[dict[str, Any]]:
    """从 AIGW MySQL 数据库拉取网关配置的 model aliases (来源 2)。
    
    环境变量:
      AIGW_DB_HOST (默认 gaiasec-llm-gateway-mysql)
      AIGW_DB_PORT (默认 3306)
      AIGW_DB_USER (默认 sa)
      AIGW_DB_PASSWORD
      AIGW_DB_NAME (默认 gaiasec_llm_gateway)
    """
    host = os.environ.get("AIGW_DB_HOST", "gaiasec-llm-gateway-mysql")
    port = int(os.environ.get("AIGW_DB_PORT", "3306"))
    user = os.environ.get("AIGW_DB_USER", "sa")
    password = os.environ.get("AIGW_DB_PASSWORD", "")
    db_name = os.environ.get("AIGW_DB_NAME", "gaiasec_llm_gateway")
    if not password:
        logger.warning("AIGW_DB_PASSWORD 未设置，跳过网关模型别名同步")
        return []
    try:
        import pymysql
        conn = pymysql.connect(host=host, port=port, user=user, password=password, database=db_name, connect_timeout=5)
        c = conn.cursor(pymysql.cursors.DictCursor)
        c.execute("SELECT alias_name, max_tokens_default, temperature_default, enabled, description FROM model_aliases")
        rows = c.fetchall()
        conn.close()
        logger.info("从 AIGW DB 同步 %d 个 model aliases", len(rows))
        return rows
    except Exception as e:
        logger.warning("AIGW DB model aliases 同步失败: %s", e)
        return []


def sync_providers_to_pi(
    base_url: str,
    token: str = "",
    timeout: int = 30,
) -> bool:
    """
    从配置中心拉取所有 LLM Provider，写入 pi 的 models.json。

    - 如果 models.json 原来是符号链接，先删除再写入真实文件。
    - 失败时保留现有 models.json，返回 False。
    """
    url = f"{base_url.rstrip('/')}/service/llm/providers"
    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        resp = httpx.get(url, headers=headers, timeout=timeout)
        if resp.status_code != 200:
            logger.warning("配置中心返回 HTTP %s，跳过 Provider 同步", resp.status_code)
            return False

        data = resp.json()
        items: list[dict] = data.get("items", [])
        if not items:
            logger.warning("配置中心返回空 Provider 列表，跳过同步")
            return False

        models_json = build_models_json(items, gateway_model_aliases=_fetch_gateway_model_aliases())
        enabled_count = len(models_json["providers"])

        pi_dir = Path(_PI_DIR)
        pi_dir.mkdir(parents=True, exist_ok=True)
        models_path = pi_dir / "models.json"

        # 若原来是 symlink（entrypoint.sh 创建），先移除
        if models_path.is_symlink():
            models_path.unlink()

        models_path.write_text(
            json.dumps(models_json, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        logger.info(
            "已从配置中心同步 %d 个 Provider 到 %s", enabled_count, models_path
        )
        for provider_key, provider_cfg in models_json["providers"].items():
            for model in provider_cfg.get("models", []):
                logger.info(
                    "LLM Provider %s/%s contextWindow=%s maxTokens=%s",
                    provider_key,
                    model.get("id"),
                    model.get("contextWindow"),
                    model.get("maxTokens"),
                )
        return True

    except httpx.RequestError as e:
        logger.error("连接配置中心失败，跳过同步: %s", e)
    except Exception as e:
        logger.exception("同步 LLM Provider 时发生未知错误: %s", e)
    return False
