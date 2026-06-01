#!/usr/bin/env python3

"""LLM 调用客户端 — 默认外网(Claude Code skill)，配置后走内网 API。

使用方式:
  from llm_client import LLMClient
  client = LLMClient(config_path)
  report = client.generate(prompt, context_json_str)
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

try:
    import urllib.request
    import urllib.error
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False


class ExternalLLMClient:
    """外网 LLM — Claude Code skill 模式。不实际调 API，而是输出 prompt+data 到文件，由 Claude Code 会话读取并生成。"""

    def generate(self, prompt: str, context_data: str, output_dir: Path) -> str:
        prompt_file = output_dir / "llm_prompt_input.md"
        data_file = output_dir / "llm_context_input.json"
        prompt_file.write_text(prompt, encoding="utf-8")
        data_file.write_text(context_data, encoding="utf-8")
        marker = (
            "EXTERNAL_LLM_PENDING\n"
            "由 Claude Code skill 读取 llm_prompt_input.md + llm_context_input.json 后生成报告。\n"
            "此文件为占位符，实际报告由 skill 流程填充。\n"
        )
        return marker


class InternalLLMClient:
    """内网 LLM — OpenAI 兼容协议（适用于 glm-5.1 等国产模型）。"""

    def __init__(self, base_url: str, api_key: str, model: str, timeout: int = 120):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    def generate(self, prompt: str, context_data: str, output_dir: Path) -> str:
        if not HAS_URLLIB:
            raise RuntimeError("urllib not available, cannot call internal LLM API")

        messages = [
            {"role": "system", "content": "你是一名网络安全专家，负责分析 nginx 配置中的安全风险并生成专业的安全巡检报告。所有结论必须可追溯到脚本输出数据，不得自行推断未由脚本提供的关联关系。"},
            {"role": "user", "content": f"{prompt}\n\n---\n\n配置数据如下：\n\n{context_data}"},
        ]

        payload = json.dumps({
            "model": self.model,
            "messages": messages,
            "temperature": 0.3,
            "max_tokens": 8192,
        }, ensure_ascii=False)

        url = f"{self.base_url}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

        req = urllib.request.Request(url, data=payload.encode("utf-8"), headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                return body["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Internal LLM API error {e.code}: {error_body}")
        except urllib.error.URLError as e:
            raise RuntimeError(f"Internal LLM API connection error: {e.reason}")
        except Exception as e:
            raise RuntimeError(f"Internal LLM API call failed: {e}")


def create_client(config_path: Path | None = None) -> ExternalLLMClient | InternalLLMClient:
    """根据配置创建 LLM 客户端。默认外网模式。"""
    if config_path is None or not config_path.exists():
        return ExternalLLMClient()

    config = json.loads(config_path.read_text(encoding="utf-8"))
    llm_config = config.get("llm", {})
    mode = llm_config.get("mode", "external")

    if mode == "internal":
        internal = llm_config.get("internal", {})
        base_url = internal.get("base_url", "")
        api_key = internal.get("api_key", "")
        model = internal.get("model", "glm-5.1")

        if not base_url:
            print(f"[WARN] llm mode=internal 但 base_url 为空，回退到 external 模式")
            return ExternalLLMClient()

        if not api_key:
            print(f"[WARN] llm mode=internal 但 api_key 为空，尝试无认证调用")

        return InternalLLMClient(base_url=base_url, api_key=api_key, model=model)

    return ExternalLLMClient()


if __name__ == "__main__":
    # Quick test
    config_path = Path("task3/TOOLS/llm_config.json")
    client = create_client(config_path)
    print(f"Client type: {type(client).__name__}")
    if isinstance(client, InternalLLMClient):
        print(f"  base_url: {client.base_url}")
        print(f"  model: {client.model}")
    else:
        print(f"  外网模式 — 由 Claude Code skill 生成报告")