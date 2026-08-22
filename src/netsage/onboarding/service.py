"""FortiOS-only device onboarding, testing, removal, and stored investigations."""

from netsage.broker import InMemoryAuditSink, ToolBroker
from netsage.credentials import (
    CredentialProfileStore,
    CredentialSecretStore,
    CredentialSecretUnavailableError,
    CredentialStoreError,
)
from netsage.drivers.fortios import (
    FORTIOS_CAPABILITIES,
    FortiOSAuthenticationError,
    FortiOSCommandError,
    FortiOSConnectionError,
    FortiOSHostKeyError,
    FortiOSParseError,
    SSHHostKeyPin,
)
from netsage.evidence import EvidenceCollector, EvidenceFactory, InMemoryEvidenceStore
from netsage.history import HistoryError, SQLiteAuditSink, SQLiteInvestigationStore
from netsage.investigations import (
    FortiOSInvestigationFocus,
    FortiOSInvestigator,
    InvestigationReport,
)
from netsage.models import CredentialReference, DeviceFacts, DeviceRef, Platform
from netsage.onboarding.models import CheckStatus, DeviceReadiness, DeviceTestResult
from netsage.onboarding.runtime import FortiOSRuntimeFactory, PreparedFortiOSRuntime
from netsage.state import (
    LocalState,
    SSHHostIdentityChangedError,
    SSHHostTrustManager,
    SSHHostTrustRecord,
    SSHTrustError,
)
from netsage.tools import FortiOSToolSet


class DeviceOnboardingError(RuntimeError):
    def __init__(self, result: DeviceTestResult) -> None:
        super().__init__(result.detail)
        self.result = result


class InvestigationHistoryWriteError(RuntimeError):
    def __init__(self, report: InvestigationReport) -> None:
        super().__init__("Investigation completed, but local history persistence failed")
        self.report = report


class FortiOSDeviceService:
    """Manage persistent FortiOS devices without configuration or raw command access."""

    def __init__(
        self,
        *,
        state: LocalState,
        secrets: CredentialSecretStore,
        trust: SSHHostTrustManager | None = None,
        runtime: FortiOSRuntimeFactory | None = None,
    ) -> None:
        self._state = state
        self._profiles: CredentialProfileStore = state.credentials
        self._trust = trust or SSHHostTrustManager(state.host_trust)
        self._runtime = runtime or FortiOSRuntimeFactory(
            profiles=self._profiles, secrets=secrets, trust=self._trust
        )

    def list_devices(self) -> tuple[DeviceRef, ...]:
        inventory = self._state.load_inventory()
        return tuple(inventory.devices[name] for name in sorted(inventory.devices))

    def show_device(self, name: str) -> tuple[DeviceRef, SSHHostTrustRecord]:
        device = self._state.load_inventory().get_device(name)
        if device.trust_ref is None:
            raise ValueError("Device has no SSH trust reference")
        return device, self._state.host_trust.get(device.trust_ref)

    async def add_device(
        self,
        *,
        name: str,
        host: str,
        port: int,
        credential_ref: str,
        reviewed_pin: SSHHostKeyPin,
    ) -> DeviceTestResult:
        self._profiles.get(credential_ref)
        inventory = self._state.inventory.load()
        if name in inventory.devices:
            raise ValueError(f"Device already exists: {name}")
        device = DeviceRef(
            name=name,
            platform=Platform.FORTIOS,
            host=host,
            port=port,
            credential_ref=CredentialReference(credential_ref),
            trust_ref=name,
            capabilities=FORTIOS_CAPABILITIES,
        )
        result = await self._test_with_reviewed_pin(device, reviewed_pin)
        if result.readiness is not DeviceReadiness.READY:
            raise DeviceOnboardingError(result)
        trust_record = SSHHostTrustRecord(
            name=name,
            host=host,
            port=port,
            algorithm=reviewed_pin.algorithm,
            fingerprint=reviewed_pin.fingerprint,
        )
        self._state.host_trust.add(trust_record)
        try:
            self._state.inventory.add(device)
        except Exception:
            self._state.host_trust.remove(name, missing_ok=True)
            raise
        return result.model_copy(update={"configured": CheckStatus.PASS})

    async def test_device(self, name: str) -> DeviceTestResult:
        device = self._state.load_inventory().get_device(name)
        try:
            pin = await self._runtime.verify_host(device)
        except SSHHostIdentityChangedError as error:
            return self._result(
                device,
                DeviceReadiness.HOST_KEY_ERROR,
                configured=CheckStatus.PASS,
                reachable=CheckStatus.PASS,
                host_key=CheckStatus.FAIL,
                expected_host_key=(f"{error.expected_algorithm} {error.expected_fingerprint}"),
                received_host_key=(f"{error.received_algorithm} {error.received_fingerprint}"),
                detail="SSH host key changed; connection aborted",
            )
        except (SSHTrustError, FortiOSHostKeyError):
            return self._result(
                device,
                DeviceReadiness.HOST_KEY_ERROR,
                configured=CheckStatus.PASS,
                host_key=CheckStatus.FAIL,
                detail="SSH host identity could not be verified",
            )
        except FortiOSConnectionError:
            return self._result(
                device,
                DeviceReadiness.UNREACHABLE,
                configured=CheckStatus.PASS,
                reachable=CheckStatus.FAIL,
                host_key=CheckStatus.FAIL,
                detail="Device is unreachable",
            )
        try:
            credential = await self._runtime.resolve_credential(device)
        except CredentialSecretUnavailableError:
            return self._result(
                device,
                DeviceReadiness.CREDENTIAL_UNAVAILABLE,
                configured=CheckStatus.PASS,
                reachable=CheckStatus.PASS,
                host_key=CheckStatus.PASS,
                credential=CheckStatus.FAIL,
                detail="Credential secret unavailable",
            )
        except CredentialStoreError:
            return self._result(
                device,
                DeviceReadiness.CREDENTIAL_UNAVAILABLE,
                configured=CheckStatus.PASS,
                reachable=CheckStatus.PASS,
                host_key=CheckStatus.PASS,
                credential=CheckStatus.FAIL,
                detail="Secure credential storage is unavailable",
            )
        runtime = self._runtime.build(device, pin, credential)
        return await self._test_runtime(runtime, configured=CheckStatus.PASS)

    def remove_device(self, name: str) -> None:
        _inventory, device = self._state.inventory.remove(name)
        try:
            if device.trust_ref is not None:
                self._state.host_trust.remove(device.trust_ref, missing_ok=True)
        except Exception:
            self._state.inventory.add(device)
            raise

    async def discover_host_key(self, *, host: str, port: int) -> SSHHostKeyPin:
        return await self._trust.discover(host, port)

    async def discover_replacement_key(self, name: str) -> tuple[DeviceRef, SSHHostKeyPin]:
        device = self._state.load_inventory().get_device(name)
        return device, await self._trust.discover(device.host, device.port)

    def replace_trust(self, device: DeviceRef, pin: SSHHostKeyPin) -> None:
        if device.trust_ref is None:
            raise ValueError("Device has no SSH trust reference")
        self._trust.replace(
            name=device.trust_ref,
            host=device.host,
            port=device.port,
            pin=pin,
        )

    async def investigate(
        self,
        name: str,
        *,
        persist: bool = True,
        focus: FortiOSInvestigationFocus = FortiOSInvestigationFocus.HEALTH,
    ) -> InvestigationReport:
        inventory = self._state.load_inventory()
        device = inventory.get_device(name)
        runtime = await self._runtime.prepare(device)
        device = device.model_copy(update={"capabilities": runtime.driver.capabilities})
        inventory = inventory.model_copy(
            update={"devices": {**inventory.devices, device.name: device}}
        )
        audit_sink = (
            SQLiteAuditSink(self._state.history, redactor=runtime.redactor)
            if persist
            else InMemoryAuditSink()
        )
        broker = ToolBroker(
            inventory=inventory,
            redactor=runtime.redactor,
            audit_sink=audit_sink,
            user="local-cli",
            ai_provider=None,
        )
        FortiOSToolSet({device.name: runtime.driver}).register(broker)
        store = InMemoryEvidenceStore(redactor=runtime.redactor)
        collector = EvidenceCollector(
            broker=broker,
            inventory=inventory,
            factory=EvidenceFactory(redactor=runtime.redactor),
            store=store,
            driver="FortiOSDriver",
        )
        report = await FortiOSInvestigator(
            collector=collector,
            redactor=runtime.redactor,
        ).investigate(device.name, focus)
        if persist:
            evidence = store.list_for_investigation(report.investigation.investigation_id)
            try:
                SQLiteInvestigationStore(
                    self._state.history,
                    redactor=runtime.redactor,
                ).add(report, evidence)
            except (HistoryError, ValueError) as error:
                raise InvestigationHistoryWriteError(report) from error
        return report

    async def _test_with_reviewed_pin(
        self, device: DeviceRef, pin: SSHHostKeyPin
    ) -> DeviceTestResult:
        try:
            runtime = await self._runtime.prepare_with_reviewed_pin(device, pin)
        except CredentialSecretUnavailableError:
            return self._result(
                device,
                DeviceReadiness.CREDENTIAL_UNAVAILABLE,
                configured=CheckStatus.NOT_RUN,
                reachable=CheckStatus.PASS,
                host_key=CheckStatus.PASS,
                credential=CheckStatus.FAIL,
                detail="Credential secret unavailable",
            )
        except CredentialStoreError:
            return self._result(
                device,
                DeviceReadiness.CREDENTIAL_UNAVAILABLE,
                configured=CheckStatus.NOT_RUN,
                reachable=CheckStatus.PASS,
                host_key=CheckStatus.PASS,
                credential=CheckStatus.FAIL,
                detail="Secure credential storage is unavailable",
            )
        return await self._test_runtime(runtime, configured=CheckStatus.NOT_RUN)

    async def _test_runtime(
        self,
        runtime: PreparedFortiOSRuntime,
        *,
        configured: CheckStatus,
    ) -> DeviceTestResult:
        device = runtime.device
        try:
            facts = await runtime.driver.get_facts()
        except FortiOSAuthenticationError:
            return self._result(
                device,
                DeviceReadiness.AUTHENTICATION_FAILED,
                configured=configured,
                reachable=CheckStatus.PASS,
                host_key=CheckStatus.PASS,
                credential=CheckStatus.PASS,
                authentication=CheckStatus.FAIL,
                detail="FortiOS SSH authentication failed",
            )
        except FortiOSConnectionError:
            return self._result(
                device,
                DeviceReadiness.UNREACHABLE,
                configured=configured,
                reachable=CheckStatus.FAIL,
                host_key=CheckStatus.PASS,
                credential=CheckStatus.PASS,
                authentication=CheckStatus.NOT_RUN,
                detail="Device is unreachable",
            )
        except FortiOSParseError:
            return self._result(
                device,
                DeviceReadiness.FORTIOS_UNVERIFIED,
                configured=configured,
                reachable=CheckStatus.PASS,
                host_key=CheckStatus.PASS,
                credential=CheckStatus.PASS,
                authentication=CheckStatus.PASS,
                fortios=CheckStatus.FAIL,
                facts=CheckStatus.FAIL,
                detail="FortiOS facts could not be verified",
            )
        except (FortiOSCommandError, FortiOSHostKeyError):
            return self._result(
                device,
                DeviceReadiness.FAILED,
                configured=configured,
                reachable=CheckStatus.PASS,
                host_key=CheckStatus.PASS,
                credential=CheckStatus.PASS,
                detail="Read-only facts collection failed",
            )
        if facts.vendor != "Fortinet":
            return self._result(
                device,
                DeviceReadiness.FORTIOS_UNVERIFIED,
                configured=configured,
                reachable=CheckStatus.PASS,
                host_key=CheckStatus.PASS,
                credential=CheckStatus.PASS,
                authentication=CheckStatus.PASS,
                fortios=CheckStatus.FAIL,
                facts=CheckStatus.FAIL,
                detail="Device did not identify as FortiOS",
            )
        return self._result(
            device,
            DeviceReadiness.READY,
            configured=configured,
            reachable=CheckStatus.PASS,
            host_key=CheckStatus.PASS,
            credential=CheckStatus.PASS,
            authentication=CheckStatus.PASS,
            fortios=CheckStatus.PASS,
            facts=CheckStatus.PASS,
            device_facts=facts,
            detail="Device is ready",
        )

    @staticmethod
    def _result(
        device: DeviceRef,
        readiness: DeviceReadiness,
        *,
        configured: CheckStatus = CheckStatus.PASS,
        reachable: CheckStatus = CheckStatus.NOT_RUN,
        host_key: CheckStatus = CheckStatus.NOT_RUN,
        credential: CheckStatus = CheckStatus.NOT_RUN,
        authentication: CheckStatus = CheckStatus.NOT_RUN,
        fortios: CheckStatus = CheckStatus.NOT_RUN,
        facts: CheckStatus = CheckStatus.NOT_RUN,
        device_facts: DeviceFacts | None = None,
        expected_host_key: str | None = None,
        received_host_key: str | None = None,
        detail: str,
    ) -> DeviceTestResult:
        return DeviceTestResult(
            device_id=device.name,
            readiness=readiness,
            configured=configured,
            reachable=reachable,
            host_key=host_key,
            credential=credential,
            authentication=authentication,
            fortios=fortios,
            facts=facts,
            device_facts=device_facts,
            expected_host_key=expected_host_key,
            received_host_key=received_host_key,
            detail=detail,
        )
