"""Secure persistent non-secret local application state."""

from typing import TYPE_CHECKING

from netsage.state.atomic import (
    SCHEMA_VERSION,
    StateError,
    StateFileInvalidError,
    StateSchemaVersionError,
    StateWriteError,
    atomic_write_yaml,
)
from netsage.state.documents import (
    AIProviderChoice,
    AISettings,
    ApplicationSettingsDocument,
    OpenAIProviderSettings,
    OpenAIReasoningEffort,
)
from netsage.state.paths import StatePaths, default_state_directory

if TYPE_CHECKING:
    from netsage.state.application import (
        ApplicationSettingsStore,
        InvalidStateReferenceError,
        LocalState,
    )
    from netsage.state.trust import (
        DuplicateSSHTrustError,
        SSHHostIdentityChangedError,
        SSHHostTrustDocument,
        SSHHostTrustManager,
        SSHHostTrustRecord,
        SSHHostTrustStore,
        SSHTrustBindingError,
        SSHTrustError,
        SSHTrustNotFoundError,
    )

_APPLICATION_EXPORTS = {
    "ApplicationSettingsStore",
    "InvalidStateReferenceError",
    "LocalState",
}
_TRUST_EXPORTS = {
    "DuplicateSSHTrustError",
    "SSHHostIdentityChangedError",
    "SSHHostTrustDocument",
    "SSHHostTrustManager",
    "SSHHostTrustRecord",
    "SSHHostTrustStore",
    "SSHTrustBindingError",
    "SSHTrustError",
    "SSHTrustNotFoundError",
}


def __getattr__(name: str) -> object:
    if name in _APPLICATION_EXPORTS:
        from netsage.state import application

        return getattr(application, name)
    if name in _TRUST_EXPORTS:
        from netsage.state import trust

        return getattr(trust, name)
    raise AttributeError(name)


__all__ = [
    "SCHEMA_VERSION",
    "AIProviderChoice",
    "AISettings",
    "ApplicationSettingsDocument",
    "ApplicationSettingsStore",
    "DuplicateSSHTrustError",
    "InvalidStateReferenceError",
    "LocalState",
    "OpenAIProviderSettings",
    "OpenAIReasoningEffort",
    "SSHHostIdentityChangedError",
    "SSHHostTrustDocument",
    "SSHHostTrustManager",
    "SSHHostTrustRecord",
    "SSHHostTrustStore",
    "SSHTrustBindingError",
    "SSHTrustError",
    "SSHTrustNotFoundError",
    "StateError",
    "StateFileInvalidError",
    "StatePaths",
    "StateSchemaVersionError",
    "StateWriteError",
    "atomic_write_yaml",
    "default_state_directory",
]
