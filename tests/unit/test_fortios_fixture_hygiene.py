import re
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

FORTIGATE_FIXTURES = Path(__file__).parents[1] / "fixtures" / "fortigate"
FORTIOS_TESTS = Path(__file__).parent
DOCUMENTATION_NETWORKS = (
    IPv4Network("192.0.2.0/24"),
    IPv4Network("198.51.100.0/24"),
    IPv4Network("203.0.113.0/24"),
)
SYNTHETIC_HOSTNAMES = frozenset(
    {
        "forti-gateway",
        "fortigate-lab",
        "lab-fortigate-a",
    }
)
IPV4_PATTERN = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
MAC_PATTERN = re.compile(r"(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b")
HOSTNAME_PATTERN = re.compile(r"(?im)^\s*[\"']?hostname\s*:\s*(?P<hostname>[A-Za-z0-9_.-]+)")
PROMPT_PATTERN = re.compile(
    r"(?m)^\s*[\"']?(?P<hostname>[A-Za-z0-9_.-]+)"
    r"(?:\s+\([^)]+\))?\s+[#$](?:\s|$)"
)
SERIAL_PATTERN = re.compile(r"(?im)^\s*serial(?:[ -]number)?\s*[:=]")


def _fortios_test_texts() -> tuple[tuple[Path, str], ...]:
    paths = sorted(FORTIGATE_FIXTURES.glob("*.txt"))
    paths.extend(sorted(FORTIOS_TESTS.glob("test_fortios*.py")))
    return tuple((path, path.read_text(encoding="utf-8")) for path in paths)


def _is_netmask(value: IPv4Address) -> bool:
    try:
        IPv4Network(f"0.0.0.0/{value}")
    except ValueError:
        return False
    return True


def test_fortios_test_data_contains_only_safe_network_identifiers() -> None:
    for path, text in _fortios_test_texts():
        assert not SERIAL_PATTERN.search(text), f"serial-like field in {path.name}"
        for raw_address in IPV4_PATTERN.findall(text):
            address = IPv4Address(raw_address)
            assert (
                address.is_unspecified
                or _is_netmask(address)
                or any(address in network for network in DOCUMENTATION_NETWORKS)
            ), f"non-documentation IPv4 address in {path.name}"
        for raw_mac in MAC_PATTERN.findall(text):
            first_octet = int(raw_mac.split(":", maxsplit=1)[0], 16)
            assert first_octet & 0x02, f"globally administered MAC address in {path.name}"


def test_fortios_test_data_uses_only_declared_synthetic_hostnames() -> None:
    for path, text in _fortios_test_texts():
        hostname_matches = HOSTNAME_PATTERN.finditer(text)
        prompt_matches = PROMPT_PATTERN.finditer(text)
        hostnames = {match.group("hostname") for match in (*hostname_matches, *prompt_matches)}
        assert hostnames <= SYNTHETIC_HOSTNAMES, f"unexpected hostname in {path.name}"
