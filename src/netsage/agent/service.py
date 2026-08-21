"""FortiOS-only composition of deterministic evidence and AI reasoning."""

from netsage.agent.models import AgentInvestigationReport, AgentInvestigationRequest
from netsage.agent.runtime import AgentRuntime
from netsage.ai import AIContextBuilder, AIProvider
from netsage.broker import ToolBroker
from netsage.credentials import CredentialSecretStore
from netsage.evidence import EvidenceCollector, EvidenceFactory, InMemoryEvidenceStore
from netsage.history import SQLiteAuditSink
from netsage.investigations import FortiOSInvestigator
from netsage.onboarding.runtime import FortiOSRuntimeFactory
from netsage.state import LocalState, SSHHostTrustManager
from netsage.tools import FortiOSToolSet


class FortiOSAIInvestigationService:
    """Keep every AI provider behind Evidence, AgentRuntime, Broker, and driver."""

    def __init__(
        self,
        *,
        state: LocalState,
        secrets: CredentialSecretStore,
        provider: AIProvider,
        provider_name: str = "openai",
        runtime: FortiOSRuntimeFactory | None = None,
    ) -> None:
        self._state = state
        self._provider = provider
        self._provider_name = provider_name
        self._runtime = runtime or FortiOSRuntimeFactory(
            profiles=state.credentials,
            secrets=secrets,
            trust=SSHHostTrustManager(state.host_trust),
        )

    async def ask(self, device_id: str, question: str) -> AgentInvestigationReport:
        inventory = self._state.load_inventory()
        device = inventory.get_device(device_id)
        await self._provider.initialize()
        try:
            prepared = await self._runtime.prepare(device)
            broker = ToolBroker(
                inventory=inventory,
                redactor=prepared.redactor,
                audit_sink=SQLiteAuditSink(
                    self._state.history,
                    redactor=prepared.redactor,
                ),
                user="local-cli",
                ai_provider=self._provider_name,
            )
            FortiOSToolSet({device.name: prepared.driver}).register(broker)
            store = InMemoryEvidenceStore(redactor=prepared.redactor)
            collector = EvidenceCollector(
                broker=broker,
                inventory=inventory,
                factory=EvidenceFactory(redactor=prepared.redactor),
                store=store,
                driver="FortiOSDriver",
            )
            deterministic_report = await FortiOSInvestigator(
                collector=collector,
                redactor=prepared.redactor,
            ).investigate_health(device.name)
            runtime = AgentRuntime(
                provider=self._provider,
                provider_name=self._provider_name,
                broker=broker,
                collector=collector,
                evidence_store=store,
                context_builder=AIContextBuilder(redactor=prepared.redactor),
            )
            return await runtime.run(
                AgentInvestigationRequest(device_id=device.name, question=question),
                device=device,
                deterministic_report=deterministic_report,
            )
        finally:
            await self._provider.close()


# Compatibility alias for integrations written against the direct-OpenAI milestone.
FortiOSOpenAIInvestigationService = FortiOSAIInvestigationService
