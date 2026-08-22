"""Constants for the experimental ChatGPT/Codex OAuth compatibility protocol.

These values are intentionally isolated because OpenAI does not document this as
a stable third-party OAuth contract. They were verified on 2026-08-22 against
openai/codex commit 4f39251 and NousResearch/hermes-agent commit 9ddb654.
"""

CODEX_OAUTH_ISSUER = "https://auth.openai.com"
CODEX_OAUTH_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
CODEX_DEVICE_USER_CODE_PATH = "/api/accounts/deviceauth/usercode"
CODEX_DEVICE_TOKEN_PATH = "/api/accounts/deviceauth/token"  # noqa: S105 - URL path
CODEX_DEVICE_VERIFICATION_PATH = "/codex/device"
CODEX_DEVICE_REDIRECT_PATH = "/deviceauth/callback"
CODEX_OAUTH_TOKEN_PATH = "/oauth/token"  # noqa: S105 - URL path
CODEX_INFERENCE_BASE_URL = "https://chatgpt.com/backend-api/codex"
CODEX_RESPONSES_PATH = "/responses"
CODEX_MODELS_PATH = "/models?client_version=1.0.0"
CODEX_OAUTH_REFRESH_SKEW_SECONDS = 120
CODEX_DEVICE_AUTH_DEFAULT_EXPIRY_SECONDS = 15 * 60
CODEX_DEVICE_AUTH_DEFAULT_INTERVAL_SECONDS = 5
CODEX_DEVICE_AUTH_SLOW_DOWN_SECONDS = 5
CODEX_ORIGINATOR = "netsage"

EXPERIMENTAL_COMPATIBILITY_NOTICE = (
    "Experimental ChatGPT/Codex OAuth compatibility provider. Upstream protocol "
    "behavior may change without a stable third-party contract."
)
