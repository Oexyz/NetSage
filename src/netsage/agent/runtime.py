"""Bounded provider-neutral agent loop using Broker-created Evidence only."""

from collections.abc import Sequence
from uuid import UUID

from netsage.agent.models import (
    AgentErrorCategory,
    AgentInvestigationReport,
    AgentInvestigationRequest,
    AgentRuntimeLimits,
    AgentRuntimeState,
)
from netsage.ai import (
    AIContextBuilder,
    AIEvidence,
    AIFinalResponse,
    AIProvider,
    AIProviderError,
    AIToolCall,
    AIToolCallsResponse,
    AIToolParameter,
    AIToolParameterType,
    AIToolResult,
    AIToolResultStatus,
    StructuredTool,
)
from netsage.broker import ToolBroker, ToolDefinition
from netsage.evidence import (
    EvidenceCollectionFailure,
    EvidenceCollector,
    EvidenceEnvelope,
    EvidenceStore,
)
from netsage.investigations import DiagnosisStrength, InvestigationReport
from netsage.models import DeviceRef

_DESCRIPTIONS = {
    "get_device_facts": "Collect normalized device facts.",
    "get_interfaces": "Collect normalized interface state.",
    "get_vlans": "Collect normalized VLAN configuration.",
    "get_arp_table": "Collect normalized ARP entries.",
    "get_routes": "Collect normalized active routes.",
    "get_system_health": "Collect normalized system health.",
    "get_firewall_policies": "Collect normalized IPv4 firewall policies.",
    "ping": "Run a policy-controlled IP ping from the network device.",
    "traceroute": "Run a policy-controlled IP traceroute from the network device.",
}


class AgentRuntime:
    def __init__(
        self,
        *,
        provider: AIProvider,
        broker: ToolBroker,
        collector: EvidenceCollector,
        evidence_store: EvidenceStore,
        context_builder: AIContextBuilder,
        limits: AgentRuntimeLimits | None = None,
        provider_name: str = "provider",
    ) -> None:
        self._provider = provider
        self._broker = broker
        self._collector = collector
        self._evidence_store = evidence_store
        self._context_builder = context_builder
        self._limits = limits or AgentRuntimeLimits()
        self._provider_name = provider_name

    async def run(
        self,
        request: AgentInvestigationRequest,
        *,
        device: DeviceRef,
        deterministic_report: InvestigationReport,
    ) -> AgentInvestigationReport:
        investigation_id = deterministic_report.investigation.investigation_id
        if (
            request.device_id != device.name
            or deterministic_report.investigation.device_id != device.name
        ):
            return self._failed(
                deterministic_report,
                (),
                AgentErrorCategory.INVALID_RESPONSE,
            )
        definitions = self._broker.tools_for_device(device.name)
        tools = tuple(self._structured_tool(item) for item in definitions)
        tool_map = {item.name: item for item in definitions}
        results: list[AIToolResult] = []
        signatures: set[str] = set()
        call_ids: set[UUID] = set()
        total_calls = 0

        for _step in range(self._limits.max_agent_steps):
            evidence = self._evidence_store.list_for_investigation(investigation_id)
            context = self._context_builder.build(
                user_request=request.question,
                device=device,
                report=deterministic_report,
                evidence=evidence,
            )
            try:
                response = await self._provider.generate(
                    context,
                    tools=tools,
                    tool_results=tuple(results),
                )
            except AIProviderError as error:
                return self._failed(
                    deterministic_report,
                    results,
                    AgentErrorCategory.PROVIDER_FAILED,
                    provider_error_code=error.code,
                )
            if isinstance(response, AIFinalResponse):
                validation_error = self._validate_final(response, deterministic_report, evidence)
                if validation_error is not None:
                    return self._failed(deterministic_report, results, validation_error)
                return AgentInvestigationReport(
                    investigation_id=investigation_id,
                    device_id=device.name,
                    provider=self._provider_name,
                    state=AgentRuntimeState.COMPLETED,
                    deterministic_findings=deterministic_report.findings,
                    ai_assessment=response,
                    tool_results=tuple(results),
                )
            if not isinstance(response, AIToolCallsResponse):
                return self._failed(
                    deterministic_report, results, AgentErrorCategory.INVALID_RESPONSE
                )
            if len(response.tool_calls) > self._limits.max_tool_calls_per_step:
                return self._limited(
                    deterministic_report, results, AgentErrorCategory.TOOL_LIMIT_REACHED
                )
            if total_calls + len(response.tool_calls) > self._limits.max_tool_calls_total:
                return self._limited(
                    deterministic_report, results, AgentErrorCategory.TOOL_LIMIT_REACHED
                )
            for call in response.tool_calls:
                if call.call_id in call_ids:
                    return self._failed(
                        deterministic_report,
                        results,
                        AgentErrorCategory.INVALID_RESPONSE,
                    )
                call_ids.add(call.call_id)
                signature = f"{call.tool_name}:{call.arguments.model_dump_json()}"
                if signature in signatures:
                    results.append(
                        AIToolResult(
                            call_id=call.call_id,
                            tool_name=call.tool_name,
                            status=AIToolResultStatus.REPEATED_TOOL_CALL,
                        )
                    )
                    return self._failed(
                        deterministic_report,
                        results,
                        AgentErrorCategory.REPEATED_TOOL_CALL,
                    )
                signatures.add(signature)
                total_calls += 1
                results.append(
                    await self._execute(
                        call,
                        tool_map=tool_map,
                        investigation_id=investigation_id,
                        device_id=device.name,
                    )
                )
        return self._limited(deterministic_report, results, AgentErrorCategory.STEP_LIMIT_REACHED)

    async def _execute(
        self,
        call: AIToolCall,
        *,
        tool_map: dict[str, ToolDefinition],
        investigation_id: UUID,
        device_id: str,
    ) -> AIToolResult:
        definition = tool_map.get(call.tool_name)
        if definition is None:
            return AIToolResult(
                call_id=call.call_id,
                tool_name=call.tool_name,
                status=AIToolResultStatus.TOOL_DENIED,
            )
        expects_destination = "destination" in definition.required_arguments
        if expects_destination != (call.arguments.destination is not None):
            return AIToolResult(
                call_id=call.call_id,
                tool_name=call.tool_name,
                status=AIToolResultStatus.INVALID_ARGUMENTS,
            )
        arguments = (
            {"destination": str(call.arguments.destination)}
            if call.arguments.destination is not None
            else None
        )
        observation = await self._collector.collect(
            investigation_id=investigation_id,
            device_id=device_id,
            operation=call.tool_name,
            capability=definition.capability,
            arguments=arguments,
        )
        if isinstance(observation, EvidenceCollectionFailure):
            return AIToolResult(
                call_id=call.call_id,
                tool_name=call.tool_name,
                status=self._failure_status(observation),
            )
        return AIToolResult(
            call_id=call.call_id,
            tool_name=call.tool_name,
            status=AIToolResultStatus.SUCCESS,
            evidence=self._ai_evidence(observation),
        )

    @staticmethod
    def _structured_tool(definition: ToolDefinition) -> StructuredTool:
        parameters = (
            (
                AIToolParameter(
                    name="destination",
                    parameter_type=AIToolParameterType.IP_ADDRESS,
                ),
            )
            if "destination" in definition.required_arguments
            else ()
        )
        return StructuredTool(
            name=definition.name,
            description=_DESCRIPTIONS.get(definition.name, "Structured read-only operation."),
            capability=definition.capability,
            operation_class=definition.operation_class,
            parameters=parameters,
        )

    @staticmethod
    def _ai_evidence(evidence: EvidenceEnvelope) -> AIEvidence:
        return AIEvidence(
            evidence_id=evidence.evidence_id,
            source_device=evidence.device_id,
            operation=evidence.operation,
            capability=evidence.capability,
            observed_at=evidence.observed_at,
            trust=evidence.trust,
            payload=evidence.payload,
        )

    @staticmethod
    def _failure_status(failure: EvidenceCollectionFailure) -> AIToolResultStatus:
        if failure.error_type == "AuthorizationDeniedError":
            return AIToolResultStatus.TOOL_DENIED
        if failure.error_type == "UnsupportedDeviceCapabilityError":
            return AIToolResultStatus.UNSUPPORTED_CAPABILITY
        if failure.error_type in {"FortiOSConnectionError", "TimeoutError"}:
            return AIToolResultStatus.DEVICE_UNAVAILABLE
        if failure.error_type in {"InvalidToolArgumentsError", "ValueError"}:
            return AIToolResultStatus.INVALID_ARGUMENTS
        return AIToolResultStatus.COLLECTION_FAILED

    @staticmethod
    def _validate_final(
        response: AIFinalResponse,
        report: InvestigationReport,
        evidence: Sequence[EvidenceEnvelope],
    ) -> AgentErrorCategory | None:
        known_ids = {item.evidence_id for item in evidence}
        if (
            response.diagnosis_strength is not DiagnosisStrength.INSUFFICIENT
            and not response.evidence_ids
        ):
            return AgentErrorCategory.INVALID_EVIDENCE_REFERENCE
        if not set(response.evidence_ids).issubset(known_ids):
            return AgentErrorCategory.INVALID_EVIDENCE_REFERENCE
        deterministic = report.diagnosis
        if deterministic is not None and deterministic.strength is DiagnosisStrength.CONFIRMED:
            if response.diagnosis_strength is not DiagnosisStrength.CONFIRMED:
                return AgentErrorCategory.DETERMINISTIC_CONTRADICTION
            if not set(deterministic.evidence_ids).issubset(response.evidence_ids):
                return AgentErrorCategory.DETERMINISTIC_CONTRADICTION
        return None

    def _failed(
        self,
        report: InvestigationReport,
        results: Sequence[AIToolResult],
        category: AgentErrorCategory,
        *,
        provider_error_code: str | None = None,
    ) -> AgentInvestigationReport:
        return AgentInvestigationReport(
            investigation_id=report.investigation.investigation_id,
            device_id=report.investigation.device_id,
            provider=self._provider_name,
            state=AgentRuntimeState.FAILED,
            deterministic_findings=report.findings,
            tool_results=tuple(results),
            error_category=category,
            provider_error_code=provider_error_code,
        )

    def _limited(
        self,
        report: InvestigationReport,
        results: Sequence[AIToolResult],
        category: AgentErrorCategory,
    ) -> AgentInvestigationReport:
        return AgentInvestigationReport(
            investigation_id=report.investigation.investigation_id,
            device_id=report.investigation.device_id,
            provider=self._provider_name,
            state=AgentRuntimeState.LIMIT_REACHED,
            deterministic_findings=report.findings,
            tool_results=tuple(results),
            error_category=category,
        )
