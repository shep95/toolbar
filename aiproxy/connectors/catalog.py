"""Every supported provider, grouped by the home country of the company.

Each entry is enabled by setting ``<NAME>_API_KEY``. Every base URL can be
overridden with ``<NAME>_BASE_URL`` (for example to use a provider's China
region, or a new URL after a provider moves its API) without a code change.

Base URLs and auth formats were taken from each provider's official API
documentation. Entries marked ``verified=False`` could not be confirmed there
and should be checked with a real key before being offered to users.
"""

from __future__ import annotations

from .compat import ProviderSpec

CHAT = frozenset({"chat/completions"})
CHAT_EMB = frozenset({"chat/completions", "embeddings"})

CATALOG: tuple[ProviderSpec, ...] = (
    # ------------------------------------------------------------------ United States
    ProviderSpec(
        "openai", "OpenAI", "US", "https://api.openai.com/v1",
        native_paths=frozenset({"chat/completions", "completions", "embeddings", "responses"}),
        lists_models=True, inject_stream_usage=True, docs="https://platform.openai.com/docs/api-reference",
    ),
    ProviderSpec(
        "google", "Google Gemini", "US", "https://generativelanguage.googleapis.com/v1beta/openai",
        native_paths=CHAT_EMB, lists_models=True, inject_stream_usage=True,
        docs="https://ai.google.dev/gemini-api/docs/openai",
    ),
    ProviderSpec(
        "xai", "xAI Grok", "US", "https://api.x.ai/v1", native_paths=CHAT_EMB, lists_models=True,
        inject_stream_usage=True, docs="https://docs.x.ai/docs/api-reference",
    ),
    ProviderSpec("perplexity", "Perplexity Sonar", "US", "https://api.perplexity.ai", docs="https://docs.perplexity.ai"),
    ProviderSpec(
        "groq", "Groq", "US", "https://api.groq.com/openai/v1", lists_models=True,
        docs="https://console.groq.com/docs/openai",
    ),
    ProviderSpec(
        "together", "Together AI", "US", "https://api.together.ai/v1", native_paths=CHAT_EMB, lists_models=True,
        docs="https://docs.together.ai/docs/openai-api-compatibility",
    ),
    ProviderSpec(
        "fireworks", "Fireworks AI", "US", "https://api.fireworks.ai/inference/v1", native_paths=CHAT_EMB,
        lists_models=True, docs="https://docs.fireworks.ai/tools-sdks/openai-compatibility",
    ),
    ProviderSpec(
        "cerebras", "Cerebras", "US", "https://api.cerebras.ai/v1", lists_models=True,
        docs="https://inference-docs.cerebras.ai/resources/openai",
    ),
    ProviderSpec(
        "sambanova", "SambaNova", "US", "https://api.sambanova.ai/v1", native_paths=CHAT_EMB, lists_models=True,
        docs="https://docs.sambanova.ai/docs/en/features/openai-compatibility",
    ),
    ProviderSpec(
        "openrouter", "OpenRouter", "US", "https://openrouter.ai/api/v1", native_paths=CHAT_EMB, lists_models=True,
        docs="https://openrouter.ai/docs",
    ),
    ProviderSpec(
        "deepinfra", "DeepInfra", "US", "https://api.deepinfra.com/v1/openai", native_paths=CHAT_EMB,
        lists_models=True, docs="https://deepinfra.com/docs/openai_api",
    ),
    ProviderSpec(
        "nvidia", "NVIDIA NIM", "US", "https://integrate.api.nvidia.com/v1", native_paths=CHAT_EMB,
        lists_models=True, docs="https://docs.api.nvidia.com/nim/reference/llm-apis",
    ),
    ProviderSpec(
        "huggingface", "Hugging Face Inference Providers", "US", "https://router.huggingface.co/v1",
        lists_models=True, docs="https://huggingface.co/docs/inference-providers",
    ),
    # ------------------------------------------------------------------ Canada
    ProviderSpec(
        "cohere", "Cohere", "CA", "https://api.cohere.ai/compatibility/v1", native_paths=CHAT_EMB,
        docs="https://docs.cohere.com/docs/compatibility-api",
    ),
    # ------------------------------------------------------------------ France
    ProviderSpec(
        "mistral", "Mistral AI", "FR", "https://api.mistral.ai/v1",
        native_paths=frozenset({"chat/completions", "embeddings", "fim/completions"}), lists_models=True,
        rename_fields=(("max_completion_tokens", "max_tokens"), ("seed", "random_seed")),
        drop_fields=("user", "stream_options", "logit_bias", "logprobs", "top_logprobs", "store", "metadata"),
        docs="https://docs.mistral.ai/api",
    ),
    ProviderSpec(
        "lighton", "LightOn Paradigm", "FR", "https://paradigm.lighton.ai/api/v2", native_paths=CHAT_EMB,
        lists_models=True, docs="https://paradigm-academy.lighton.ai",
    ),
    # ------------------------------------------------------------------ Israel
    ProviderSpec("ai21", "AI21 Labs Jamba", "IL", "https://api.ai21.com/studio/v1", docs="https://docs.ai21.com"),
    # ------------------------------------------------------------------ China
    ProviderSpec(
        "deepseek", "DeepSeek", "CN", "https://api.deepseek.com", lists_models=True, inject_stream_usage=True,
        docs="https://api-docs.deepseek.com",
    ),
    ProviderSpec(
        "qwen", "Alibaba Qwen (Model Studio)", "CN", "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
        native_paths=CHAT_EMB, lists_models=True, inject_stream_usage=True,
        notes="China region: https://dashscope.aliyuncs.com/compatible-mode/v1",
        docs="https://www.alibabacloud.com/help/en/model-studio/compatibility-of-openai-with-dashscope",
    ),
    ProviderSpec(
        "moonshot", "Moonshot AI Kimi", "CN", "https://api.moonshot.ai/v1", lists_models=True,
        inject_stream_usage=True, notes="China region: https://api.moonshot.cn/v1",
        docs="https://platform.moonshot.ai/docs",
    ),
    ProviderSpec(
        "zhipu", "Zhipu AI GLM (Z.ai)", "CN", "https://api.z.ai/api/paas/v4", native_paths=CHAT_EMB,
        notes="China region: https://open.bigmodel.cn/api/paas/v4", docs="https://docs.z.ai",
    ),
    ProviderSpec(
        "minimax", "MiniMax", "CN", "https://api.minimax.io/v1",
        notes="China region: https://api.minimaxi.com/v1", docs="https://platform.minimax.io/docs",
    ),
    ProviderSpec(
        "baidu", "Baidu ERNIE (Qianfan)", "CN", "https://qianfan.baidubce.com/v2",
        env_headers=(("appid", "BAIDU_APPID"),), docs="https://cloud.baidu.com/doc/qianfan/s/Hmh4suq26",
    ),
    ProviderSpec(
        "tencent", "Tencent Hunyuan", "CN", "https://api.hunyuan.cloud.tencent.com/v1", native_paths=CHAT_EMB,
        inject_stream_usage=True, docs="https://cloud.tencent.com/document/product/1729/111007",
    ),
    ProviderSpec(
        "doubao", "ByteDance Doubao (ModelArk)", "CN", "https://ark.ap-southeast.bytepluses.com/api/v3",
        notes="China region (Volcengine Ark): https://ark.cn-beijing.volces.com/api/v3",
        docs="https://docs.byteplus.com/en/docs/ModelArk",
    ),
    ProviderSpec(
        "stepfun", "StepFun", "CN", "https://api.stepfun.ai/v1", lists_models=True,
        notes="China region: https://api.stepfun.com/v1", docs="https://platform.stepfun.ai/docs",
    ),
    ProviderSpec(
        "iflytek", "iFlytek Spark", "CN", "https://spark-api-open.xf-yun.com/v1",
        notes="The API key is the Spark APIPassword", docs="https://www.xfyun.cn/doc/spark/HTTP调用文档.html",
    ),
    ProviderSpec(
        "baichuan", "Baichuan", "CN", "https://api.baichuan-ai.com/v1", verified=False,
        docs="https://platform.baichuan-ai.com/docs/api",
    ),
    ProviderSpec(
        "yi", "01.AI Yi", "CN", "https://api.lingyiwanwu.com/v1", verified=False,
        notes="International platform was suspended; this is the China platform",
    ),
    # ------------------------------------------------------------------ South Korea
    ProviderSpec(
        "upstage", "Upstage Solar", "KR", "https://api.upstage.ai/v1", native_paths=CHAT_EMB,
        docs="https://console.upstage.ai/docs",
    ),
    ProviderSpec(
        "naver", "NAVER HyperCLOVA X", "KR", "https://clovastudio.stream.ntruss.com/v1/openai",
        native_paths=CHAT_EMB, docs="https://api.ncloud-docs.com/docs/en/clovastudio-openaicompatibility",
    ),
    # ------------------------------------------------------------------ Japan
    ProviderSpec(
        "sakana", "Sakana AI", "JP", "https://api.sakana.ai/v1", lists_models=True,
        docs="https://console.sakana.ai/get-started",
    ),
    ProviderSpec(
        "plamo", "Preferred Networks PLaMo", "JP", "https://api.platform.preferredai.jp/v1",
        docs="https://docs.plamo.preferredai.jp/en/api",
    ),
    # ------------------------------------------------------------------ India
    ProviderSpec(
        "sarvam", "Sarvam AI", "IN", "https://api.sarvam.ai/v1", auth="header:api-subscription-key",
        docs="https://docs.sarvam.ai/api-reference-docs/authentication",
    ),
    ProviderSpec("krutrim", "Ola Krutrim", "IN", "https://cloud.olakrutrim.com/v1", docs="https://docs.cloud.olakrutrim.com"),
    # ------------------------------------------------------------------ Singapore
    ProviderSpec(
        "sealion", "AI Singapore SEA-LION", "SG", "https://api.sea-lion.ai/v1",
        docs="https://docs.sea-lion.ai/guides/inferencing/api",
    ),
    # ------------------------------------------------------------------ United Arab Emirates
    ProviderSpec("ai71", "AI71 Falcon (TII)", "AE", "https://api.ai71.ai/v1", verified=False),
    # ------------------------------------------------------------------ Russia
    ProviderSpec(
        "yandex", "YandexGPT (Yandex AI Studio)", "RU", "https://llm.api.cloud.yandex.net/v1",
        auth="scheme:Api-Key", env_headers=(("OpenAI-Project", "YANDEX_FOLDER_ID"),),
        model_template_env="YANDEX_FOLDER_ID",
        notes="Set YANDEX_FOLDER_ID; model 'yandexgpt/latest' becomes gpt://<folder>/yandexgpt/latest",
        docs="https://yandex.cloud/en/docs/ai-studio/concepts/openai-compatibility",
    ),
    ProviderSpec(
        "gigachat", "Sber GigaChat", "RU", "https://gigachat.devices.sberbank.ru/api/v1", native_paths=CHAT_EMB,
        auth="oauth:gigachat",
        extra={"oauth_url": "https://ngw.devices.sberbank.ru:9443/api/v2/oauth", "oauth_scope": "GIGACHAT_API_PERS"},
        notes=(
            "GIGACHAT_API_KEY is the base64 authorization key; tokens are refreshed automatically. "
            "Set GIGACHAT_SCOPE for B2B/CORP and UPSTREAM_EXTRA_CA_FILE to the Russian Trusted Root CA."
        ),
        docs="https://developers.sber.ru/docs/ru/gigachat/guides/compatible-openai",
    ),
)
