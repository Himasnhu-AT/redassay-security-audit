"""Reachability: what this repository publishes to a network it does not control.

Every other scanner asks whether a line of code is dangerous. This one asks a
prior question - can anyone outside reach it at all - because the answer changes
what everything else means. A SQL injection behind a service bound to loopback
is a bug to schedule; the same injection behind a container publishing 0.0.0.0
is an incident waiting for someone to notice.

The unit here is a *published service*, not a line: a compose port mapping, a
Kubernetes Service, a security group, a process binding a wildcard address. Each
finding names the port, what is behind it, and how far it reaches.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Sequence, Tuple

from ..models import Finding
from ..walker import SourceFile
from .base import ScanContext, Scanner
from .registry import register

# --- what is behind the port -------------------------------------------------
#: Ports whose services are never meant to face a hostile network. Publishing
#: one is a different class of mistake from publishing an HTTP port.
SENSITIVE_PORTS: Dict[int, str] = {
    22: "SSH", 23: "Telnet", 25: "SMTP", 111: "rpcbind", 135: "MSRPC",
    139: "NetBIOS", 445: "SMB", 512: "rexec", 513: "rlogin", 514: "rsh",
    1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 2181: "ZooKeeper",
    2375: "Docker API (plaintext)", 2376: "Docker API", 2379: "etcd",
    3000: "app/dev server", 3306: "MySQL", 3389: "RDP", 4444: "debug/ops",
    5000: "app/dev server", 5432: "PostgreSQL", 5601: "Kibana",
    5672: "RabbitMQ", 5900: "VNC", 5984: "CouchDB", 6379: "Redis",
    6443: "Kubernetes API", 7001: "WebLogic", 8020: "HDFS", 8086: "InfluxDB",
    8123: "ClickHouse", 8500: "Consul", 8983: "Solr", 9000: "app/console",
    9042: "Cassandra", 9092: "Kafka", 9200: "Elasticsearch", 9300: "Elasticsearch transport",
    11211: "Memcached", 15672: "RabbitMQ management", 27017: "MongoDB",
    27018: "MongoDB", 50070: "HDFS NameNode",
}

#: Data stores and control planes. Publishing these is critical regardless of
#: what else is true, because most ship with no authentication by default.
CRITICAL_PORTS = {
    1433, 1521, 2049, 2181, 2375, 2376, 2379, 3306, 5432, 5672, 5984, 6379,
    6443, 8020, 8086, 8123, 8500, 9042, 9092, 9200, 9300, 11211, 27017, 27018,
    50070, 445, 3389, 5900, 23, 512, 513, 514,
}

ANY_ADDRESS = {"0.0.0.0", "::", "[::]", "*", ""}

# --- compose -----------------------------------------------------------------
#: "8080:80", "0.0.0.0:8080:80", "127.0.0.1:8080:80", "8080:80/tcp"
_COMPOSE_PORT = re.compile(
    r"""^\s*-\s*["']?"""
    r"""(?:(?P<host_ip>\[?[0-9a-fA-F:.]+\]?):)?"""
    r"""(?P<host_port>\d{1,5})(?:-\d{1,5})?"""
    r""":(?P<container_port>\d{1,5})(?:-\d{1,5})?"""
    r"""(?:/(?:tcp|udp))?["']?\s*$"""
)
#: The short form - `- 80` or `- "80"` with no host side. Docker publishes it on
#: an *ephemeral host port bound to every interface*, which is the least obvious
#: and most common way a compose file ends up reachable from the network: it
#: looks like it is only naming a container port.
_COMPOSE_SHORT_ONLY = re.compile(r"""^\s*-\s*["']?(?P<container_port>\d{1,5})(?:/(?:tcp|udp))?["']?\s*$""")

_COMPOSE_LONG_PUBLISHED = re.compile(r"^\s*published\s*:\s*[\"']?(?P<host_port>\d{1,5})")
_COMPOSE_LONG_HOST_IP = re.compile(r"^\s*host_ip\s*:\s*[\"']?(?P<host_ip>[0-9a-fA-F:.]+)")
_COMPOSE_SERVICE = re.compile(r"^  (?P<name>[A-Za-z0-9_.-]+)\s*:\s*$")
_COMPOSE_IMAGE = re.compile(r"^\s*image\s*:\s*[\"']?(?P<image>[^\s\"']+)")

# --- kubernetes --------------------------------------------------------------
# A key can be the first entry of a list item ("- hostPort: 6379") or a later
# one ("  hostPort: 6379"). Both are ordinary YAML; only allowing the second
# meant the rule missed the more common spelling.
_K8S_SERVICE_TYPE = re.compile(r"^\s*-?\s*type\s*:\s*(?P<type>LoadBalancer|NodePort)\s*$")
_K8S_NODE_PORT = re.compile(r"^\s*-?\s*nodePort\s*:\s*(?P<port>\d+)")
_K8S_HOST_PORT = re.compile(r"^\s*-?\s*hostPort\s*:\s*(?P<port>\d+)")
_K8S_INGRESS = re.compile(r"^\s*kind\s*:\s*Ingress\s*$")

# --- cloud -------------------------------------------------------------------
_OPEN_CIDR = re.compile(r"(0\.0\.0\.0/0|::/0)")
_PORT_RANGE = re.compile(r"(?:from_port|FromPort|port)\s*[=:]\s*[\"']?(?P<port>\d{1,5})")

# --- process binding ---------------------------------------------------------
_BIND_ALL = re.compile(
    r"""(?:host|HOST|hostname|bind|BIND|address|listen|ListenAddress)\s*[=:]\s*"""
    r"""[\"']?(?P<addr>0\.0\.0\.0|::|\*)[\"']?"""
    r"""|\.(?:listen|bind|run)\s*\(\s*[^)]*[\"'](?P<addr2>0\.0\.0\.0|::)[\"']"""
    r"""|--host[= ][\"']?(?P<addr3>0\.0\.0\.0|::)"""
)
_PORT_NEARBY = re.compile(r"(?:port|PORT)\s*[=:]\s*[\"']?(?P<port>\d{1,5})")

# --- dockerfile --------------------------------------------------------------
_EXPOSE = re.compile(r"^\s*EXPOSE\s+(?P<ports>[\d\s/tcpud]+)", re.IGNORECASE)


@dataclass
class Service:
    """One published listener."""

    port: int
    host_ip: str = "0.0.0.0"
    container_port: int = 0
    name: str = ""
    image: str = ""
    kind: str = "port-mapping"

    @property
    def service_label(self) -> str:
        known = SENSITIVE_PORTS.get(self.container_port or self.port)
        if known:
            return known
        if self.image:
            return self.image.split("/")[-1].split(":")[0]
        return self.name or "service"

    @property
    def is_critical(self) -> bool:
        return (self.container_port or self.port) in CRITICAL_PORTS

    @property
    def reaches_everyone(self) -> bool:
        return self.host_ip in ANY_ADDRESS


def _loopback(address: str) -> bool:
    return address.startswith("127.") or address in {"::1", "[::1]", "localhost"}


@register
class ExposureScanner(Scanner):
    name = "exposure"
    description = "Published services: port mappings, Kubernetes Services, open CIDRs, wildcard binds"

    def applies_to(self, source: SourceFile) -> bool:
        name = os.path.basename(source.path).lower()
        if source.language in {"compose", "yaml", "dockerfile", "terraform", "json"}:
            return True
        if name.startswith("docker-compose") or name.startswith("compose."):
            return True
        return source.language in {"python", "javascript", "typescript", "go", "ruby", "shell"}

    def scan_file(self, source: SourceFile, context: ScanContext) -> Iterator[Finding]:
        name = os.path.basename(source.path).lower()
        lines = source.lines()

        if name.startswith(("docker-compose", "compose.")) or source.language == "compose":
            yield from self._compose(source, lines)
        if source.language in {"yaml", "compose"}:
            yield from self._kubernetes(source, lines)
        if source.language in {"terraform", "json", "yaml"}:
            yield from self._cloud(source, lines)
        if source.language == "dockerfile":
            yield from self._dockerfile(source, lines)
        if source.language in {"python", "javascript", "typescript", "go", "ruby", "shell"}:
            yield from self._binds(source, lines)

    # -- docker compose ------------------------------------------------------
    def _compose(self, source: SourceFile, lines: Sequence[str]) -> Iterator[Finding]:
        service_name = ""
        image = ""
        pending_host_ip: Optional[str] = None
        # `ports:` publishes to the host; `expose:` only opens the port to other
        # services on the same network. Conflating them would report every
        # internal database link as an exposure.
        in_ports_block = False
        ports_indent = 0

        for index, line in enumerate(lines):
            if line.strip().startswith("#"):
                continue

            stripped = line.strip()
            indent = len(line) - len(line.lstrip())
            if stripped in ("ports:", "expose:"):
                in_ports_block = stripped == "ports:"
                ports_indent = indent
                continue
            if stripped and indent <= ports_indent and not stripped.startswith("-"):
                in_ports_block = False
            service = _COMPOSE_SERVICE.match(line)
            if service:
                service_name, image = service.group("name"), ""
                continue
            image_match = _COMPOSE_IMAGE.match(line)
            if image_match:
                image = image_match.group("image")
                continue

            if in_ports_block:
                short_only = _COMPOSE_SHORT_ONLY.match(line)
                if short_only:
                    container_port = int(short_only.group("container_port"))
                    yield self._short_form_finding(source, index + 1, line, container_port,
                                                   service_name, image)
                    continue

            host_ip_match = _COMPOSE_LONG_HOST_IP.match(line)
            if host_ip_match:
                pending_host_ip = host_ip_match.group("host_ip")
                continue

            if not in_ports_block:
                # Under `expose:`, a port is opened to the compose network only.
                # Reporting those as published would flag every internal
                # database link in every stack.
                continue

            published = _COMPOSE_LONG_PUBLISHED.match(line)
            short = _COMPOSE_PORT.match(line)
            if not published and not short:
                continue

            if short:
                host_ip = short.group("host_ip") or "0.0.0.0"
                host_port = int(short.group("host_port"))
                container_port = int(short.group("container_port"))
            else:
                host_ip = pending_host_ip or "0.0.0.0"
                host_port = int(published.group("host_port"))
                container_port = host_port
                pending_host_ip = None

            host_ip = host_ip.strip("[]")
            if _loopback(host_ip):
                continue        # bound to the host only; not published

            service_info = Service(
                port=host_port, host_ip=host_ip, container_port=container_port,
                name=service_name, image=image,
            )
            yield self._service_finding(source, index + 1, line, service_info,
                                        origin="a compose port mapping")

    def _short_form_finding(self, source: SourceFile, line_no: int, line: str,
                            container_port: int, service_name: str, image: str) -> Finding:
        """`- 80` under `ports:` - published on a random host port, all interfaces."""
        service = Service(port=0, host_ip="0.0.0.0", container_port=container_port,
                          name=service_name, image=image)
        label = service.service_label
        critical = service.is_critical
        return self.make_finding(
            rule_id="expose.published-ephemeral",
            title=(f"{label} published on a random host port"
                   if label != "service" else
                   f"Container port {container_port} published on a random host port"),
            source=source, line=line_no, snippet=line.strip(),
            severity="critical" if critical else "medium",
            confidence="high",
            description=(
                f"A `ports:` entry with only a container port publishes it anyway - Docker picks "
                f"a free host port and binds it to 0.0.0.0. It reads like a declaration that the "
                f"container listens on {container_port}, which is what `expose:` does; `ports:` "
                f"makes it reachable from every interface the host has."
                + (f" {label} is a data store or control plane." if critical else "")
            ),
            remediation=(
                "Keep the random port and confine it to loopback by giving the host side an "
                f"address and no port: `- \"127.0.0.1::{container_port}\"`. If nothing outside "
                f"the compose network needs it, use `expose:` instead - services reach each other "
                f"by name on {container_port} without publishing anything."
            ),
            cwe=["CWE-668"], owasp=["A05:2021 Security Misconfiguration"],
            tags=["exposure", "docker"] + (["datastore"] if critical else []),
            scanner=self.name,
            salt=str(container_port),
        )

    # -- kubernetes ----------------------------------------------------------
    def _kubernetes(self, source: SourceFile, lines: Sequence[str]) -> Iterator[Finding]:
        text = "\n".join(lines)
        if "kind:" not in text:
            return

        for index, line in enumerate(lines):
            type_match = _K8S_SERVICE_TYPE.match(line)
            if type_match:
                kind = type_match.group("type")
                yield self.make_finding(
                    rule_id=f"expose.k8s-{kind.lower()}",
                    title=f"Service of type {kind} publishes the workload outside the cluster",
                    source=source, line=index + 1, snippet=line.strip(),
                    severity="high" if kind == "LoadBalancer" else "medium",
                    confidence="high",
                    description=(
                        f"A {kind} Service allocates a routable address for this workload. "
                        + ("A LoadBalancer gets a public IP from the cloud provider unless an "
                           "internal-load-balancer annotation says otherwise."
                           if kind == "LoadBalancer" else
                           "A NodePort opens the same high port on every node, which is reachable "
                           "by anything that can route to a node.")
                        + " Whatever authentication the workload has is now the only control."
                    ),
                    remediation=(
                        "Use ClusterIP and reach it through an ingress that terminates TLS and "
                        "authenticates, or annotate the service as internal if the cloud supports it."
                    ),
                    cwe=["CWE-668"], owasp=["A05:2021 Security Misconfiguration"],
                    tags=["exposure", "kubernetes"], scanner=self.name,
                )
                continue

            host_port = _K8S_HOST_PORT.match(line)
            if host_port:
                port = int(host_port.group("port"))
                yield self.make_finding(
                    rule_id="expose.k8s-host-port",
                    title=f"hostPort {port} binds the container to the node's network",
                    source=source, line=index + 1, snippet=line.strip(),
                    severity="high" if port in CRITICAL_PORTS else "medium",
                    confidence="high",
                    description=(
                        f"hostPort bypasses Service routing and binds port {port} directly on "
                        "whichever node runs the pod"
                        + (f" - and {SENSITIVE_PORTS.get(port, 'that service')} is not something to "
                           "expose on a node interface." if port in SENSITIVE_PORTS else ".")
                    ),
                    remediation="Remove hostPort and route through a Service.",
                    cwe=["CWE-668"], owasp=["A05:2021 Security Misconfiguration"],
                    tags=["exposure", "kubernetes"], scanner=self.name,
                )

    # -- cloud ---------------------------------------------------------------
    def _cloud(self, source: SourceFile, lines: Sequence[str]) -> Iterator[Finding]:
        for index, line in enumerate(lines):
            if not _OPEN_CIDR.search(line):
                continue
            window = "\n".join(lines[max(0, index - 6):index + 3])
            port_match = _PORT_RANGE.search(window)
            port = int(port_match.group("port")) if port_match else 0
            label = SENSITIVE_PORTS.get(port, "")
            severity = "critical" if port in CRITICAL_PORTS else "high"
            yield self.make_finding(
                rule_id="expose.open-cidr",
                title=(f"{label} (port {port}) open to the entire internet" if label
                       else "Ingress rule open to the entire internet"),
                source=source, line=index + 1, snippet=line.strip(),
                severity=severity, confidence="medium" if not port else "high",
                description=(
                    "0.0.0.0/0 means every address on the internet. "
                    + (f"Port {port} is {label}, which is not designed to be reachable from an "
                       "untrusted network - most deployments of it have no authentication at all."
                       if label and port in CRITICAL_PORTS else
                       f"Anything listening on port {port} is directly reachable." if port else
                       "Whatever this rule fronts is directly reachable.")
                ),
                remediation=(
                    "Scope the CIDR to the addresses that actually need it - a VPC range, a VPN "
                    "block, an office prefix. If it genuinely must be public, put an "
                    "authenticating proxy in front rather than the service itself."
                ),
                cwe=["CWE-284"], owasp=["A05:2021 Security Misconfiguration"],
                tags=["exposure", "cloud"], scanner=self.name,
            )

    # -- dockerfile ----------------------------------------------------------
    def _dockerfile(self, source: SourceFile, lines: Sequence[str]) -> Iterator[Finding]:
        for index, line in enumerate(lines):
            match = _EXPOSE.match(line)
            if not match:
                continue
            for raw in re.findall(r"\d{1,5}", match.group("ports")):
                port = int(raw)
                if port not in CRITICAL_PORTS:
                    continue
                yield self.make_finding(
                    rule_id="expose.dockerfile-datastore-port",
                    title=f"Image declares {SENSITIVE_PORTS.get(port, 'a data store')} on port {port}",
                    source=source, line=index + 1, snippet=line.strip(),
                    severity="medium", confidence="medium",
                    description=(
                        f"EXPOSE {port} documents that this image serves "
                        f"{SENSITIVE_PORTS.get(port, 'a data store')}. EXPOSE alone publishes "
                        "nothing, but it is what `docker run -P` maps to a random host port, and "
                        "it tells whoever writes the compose file that this is a port to map."
                    ),
                    remediation=(
                        "Keep data stores on an internal network and do not publish them. If the "
                        "EXPOSE is only documentation, say so in a comment next to it."
                    ),
                    cwe=["CWE-668"], owasp=["A05:2021 Security Misconfiguration"],
                    tags=["exposure", "docker"], scanner=self.name,
                )

    # -- process binds -------------------------------------------------------
    def _binds(self, source: SourceFile, lines: Sequence[str]) -> Iterator[Finding]:
        seen = 0
        for index, line in enumerate(lines):
            if line.strip().startswith(("#", "//")):
                continue
            match = _BIND_ALL.search(line)
            if not match:
                continue
            window = "\n".join(lines[max(0, index - 3):index + 4])
            port_match = _PORT_NEARBY.search(window)
            port = int(port_match.group("port")) if port_match else 0
            seen += 1
            if seen > 10:
                return
            yield self.make_finding(
                rule_id="expose.wildcard-bind",
                title=f"Process listens on every interface{f' (port {port})' if port else ''}",
                source=source, line=index + 1, snippet=line.strip(),
                severity="high" if port in CRITICAL_PORTS else "low",
                confidence="medium",
                description=(
                    "Binding 0.0.0.0 accepts connections on every interface the host has, "
                    "including ones you did not mean to serve. Inside a container that is often "
                    "correct - the container network is the boundary - but on a host, or in a "
                    "container with host networking, it is the difference between a local service "
                    "and a public one."
                    + (f" Port {port} is {SENSITIVE_PORTS[port]}." if port in SENSITIVE_PORTS else "")
                ),
                remediation=(
                    "Bind 127.0.0.1 and front it with a reverse proxy, or bind the specific "
                    "private interface. If the wildcard is deliberate because a container network "
                    "provides the boundary, say so in a comment."
                ),
                cwe=["CWE-1327"], owasp=["A05:2021 Security Misconfiguration"],
                tags=["exposure", "binding"], scanner=self.name,
                salt="" if seen == 1 else str(seen),
            )

    # -- shared --------------------------------------------------------------
    def _service_finding(self, source: SourceFile, line_no: int, line: str,
                         service: Service, origin: str) -> Finding:
        label = service.service_label
        critical = service.is_critical
        target = service.container_port or service.port
        return self.make_finding(
            rule_id="expose.published-datastore" if critical else "expose.published-port",
            title=(f"{label} published on port {service.port}" if critical
                   else f"Port {service.port} published to the host"),
            source=source, line=line_no, snippet=line.strip(),
            severity="critical" if critical else "medium",
            confidence="high",
            description=(
                f"{origin.capitalize()} binds host {service.host_ip}:{service.port} to container "
                f"port {target}"
                + (f" ({label})." if label != "service" else ".")
                + (
                    f" {label} is a data store or control plane. Published this way it is "
                    "reachable from anything that can route to the host, and most images ship "
                    "with authentication disabled for local development."
                    if critical else
                    " Anything that can route to the host can reach it."
                )
            ),
            remediation=(
                "Drop the host mapping entirely - services on the same compose network reach each "
                f"other by name on port {target} without publishing. If you need it locally, bind "
                f"loopback explicitly: \"127.0.0.1:{service.port}:{target}\"."
            ),
            cwe=["CWE-668"], owasp=["A05:2021 Security Misconfiguration"],
            tags=["exposure", "docker"] + (["datastore"] if critical else []),
            scanner=self.name,
            salt=f"{service.port}:{target}",
        )
