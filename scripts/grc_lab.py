"""Dedicated it-grc Lima VM that runs the unmodified CISO Assistant CE through its chart.

The script acts only on the Lima instance `it-grc` whose owner parameter, mounts and port
forwards match deploy/lima/it-grc.yaml, and only on the Kubernetes namespace it labels as
its own. Secrets are generated here, kept in owner-only files under deploy/.data and passed
to the guest on stdin. They are never printed, logged or placed on a command line.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import http.client
import io
import json
import os
import re
import secrets
import ssl
import stat
import subprocess
import sys
import tarfile
import time
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DEPLOY = ROOT / "deploy"
PROFILE = DEPLOY / "lima/it-grc.yaml"
VALUES = DEPLOY / "helm/values.yaml"
UPSTREAM = DEPLOY / "upstream.json"
DATA = DEPLOY / ".data"

VM = "it-grc"
OWNER = "it-grc"
NAMESPACE = "it-grc"
RELEASE = "it-grc"
BACKEND = "it-grc-ciso-assistant-backend"
FRONTEND = "it-grc-ciso-assistant-frontend"
TLS_APP = "it-grc-tls"
OWNER_KEY = "app.kubernetes.io/part-of"
OWNER_VALUE = "it-grc-system-of-record"
FIELD_MANAGER = "it-grc-lab"
VERSION = "v4.1.1"
PORT = 18443
ORIGIN = f"https://localhost:{PORT}"
HEALTH = "/api/health/"
ADMIN_EMAIL = "admin@example.org"
GUEST_DATA = "/srv/it-grc"
FORWARD_UNIT = "it-grc-https.service"
PROBE_POD = "it-grc-netpol-probe"
DJANGO_KEY_REF = "it-grc-django"
OIDC_KEY_REF = "it-grc-oidc"
BOOTSTRAP_REF = "it-grc-bootstrap"
ADMIN_CREDENTIAL_FILE = "admin-password"
DJANGO_KEY_FILE = "django-secret-key"
CA_FILE = "ca.pem"
CADDY_UID = 65532
BACKEND_UID = 1001
# PersistentVolume name: (folder under GUEST_DATA, size, owning uid).
VOLUMES = {
    "it-grc-sqlite": ("sqlite", "2Gi", BACKEND_UID),
    "it-grc-attachments": ("attachments", "2Gi", BACKEND_UID),
    "it-grc-tls-data": ("tls", "64Mi", CADDY_UID),
}
ARCHES = ("aarch64", "x86_64")
SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
SHA512 = re.compile(r"sha512:[0-9a-f]{128}")
HEX64 = re.compile(r"\b[0-9a-f]{64}\b")
MANIFEST_TYPES = ", ".join(
    [
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    ]
)
CHART_LAYER = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"
PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S
)
CADDYFILE = f"""{{
\tadmin off
\tpersist_config off
\tskip_install_trust
\tauto_https disable_redirects
\tdefault_sni localhost
\tservers {{
\t\tstrict_sni_host on
\t}}
}}

https://localhost:{PORT} {{
\ttls internal
\thandle /api/* {{
\t\treverse_proxy {BACKEND}:80
\t}}
\thandle {{
\t\treverse_proxy {FRONTEND}:80
\t}}
}}
"""

_SECRETS: set[str] = set()


class GrcLabError(Exception):
    """Fixed, redacted messages only."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GrcLabError(message)


def redact(text: str) -> str:
    for value in sorted(_SECRETS, key=len, reverse=True):
        text = text.replace(value, "<redacted>")
    return PRIVATE_KEY.sub("<redacted private key>", text)


def shown(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def say(message: str) -> None:
    print(redact(message), flush=True)


# Pins


def load_pins(path: Path | None = None) -> dict[str, Any]:
    try:
        pins: dict[str, Any] = json.loads((path or UPSTREAM).read_text())
        for arch in ARCHES:
            image = pins["lima_image"][arch]
            require(image["location"].startswith("https://cloud.debian.org/"), "image source")
            require(bool(SHA512.fullmatch(image["digest"])), "image digest")
            for tool in ("k3s", "helm"):
                require(bool(re.fullmatch(r"[0-9a-f]{64}", pins[tool][arch]["sha256"])), tool)
        require(bool(re.fullmatch(r"v\d+\.\d+\.\d+\+k3s\d+", pins["k3s"]["version"])), "k3s")
        require(bool(re.fullmatch(r"v\d+\.\d+\.\d+", pins["helm"]["version"])), "helm")
        chart = pins["chart"]
        require(chart["registry"] == "ghcr.io", "chart registry")
        require(chart["reference"] == f"oci://ghcr.io/{chart['repository']}", "chart reference")
        require(bool(re.fullmatch(r"\d+\.\d+\.\d+", chart["version"])), "chart version")
        for key in ("digest", "content_digest"):
            require(bool(SHA256.fullmatch(chart[key])), "chart digest")
        for name in ("backend", "frontend", "caddy"):
            image = pins["images"][name]
            require(image["registry"] in {"ghcr.io", "docker.io"}, "image registry")
            require(bool(re.fullmatch(r"[a-z0-9._/-]+", image["repository"])), "repository")
            require(bool(re.fullmatch(r"[A-Za-z0-9_.-]+", image["tag"])), "image tag")
            require(bool(SHA256.fullmatch(image["digest"])), "image digest")
        for name in ("backend", "frontend"):
            require(pins["images"][name]["tag"] == VERSION, "CISO Assistant version")
    except (OSError, ValueError, KeyError, TypeError, GrcLabError):
        raise GrcLabError("deploy/upstream.json is missing or invalid") from None
    return pins


def image_ref(image: dict[str, str]) -> str:
    return f"{image['registry']}/{image['repository']}:{image['tag']}@{image['digest']}"


def check_deploy_files(pins: dict[str, Any]) -> None:
    """The tracked VM profile and Helm values use exactly the pins in upstream.json."""
    values = VALUES.read_text()
    profile = PROFILE.read_text()
    images = pins["images"]
    for name in ("backend", "frontend"):
        line = f"tag: {images[name]['tag']}@{images[name]['digest']}"
        require(line in values, f"deploy/helm/values.yaml does not pin the {name} image")
    expected = {images["backend"]["digest"], images["frontend"]["digest"]}
    require(set(SHA256.findall(values)) == expected, "Unexpected digest in Helm values")
    lima = {pins["lima_image"][arch]["digest"] for arch in ARCHES}
    require(set(SHA512.findall(profile)) == lima, "Lima image digests differ from pins")
    for arch in ARCHES:
        require(pins["lima_image"][arch]["location"] in profile, "Lima image location differs")
    tools = {pins[tool][arch]["sha256"] for tool in ("k3s", "helm") for arch in ARCHES}
    require(set(HEX64.findall(profile)) == tools, "k3s or Helm checksum differs from pins")
    for tool in ("k3s", "helm"):
        line = f"{tool}_version='{pins[tool]['version']}'"
        require(line in profile, f"Lima profile does not pin {tool}")


def fetch(url: str, headers: dict[str, str] | None = None) -> tuple[bytes, dict[str, str]]:
    require(url.startswith("https://"), "Only HTTPS sources are allowed")
    request = urllib.request.Request(url)
    for key, value in (headers or {}).items():
        # Unredirected: a registry token never follows a redirect to a blob CDN.
        request.add_unredirected_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            return response.read(), {k.lower(): v for k, v in response.headers.items()}
    except OSError:
        raise GrcLabError("Pin verification source unavailable: " + url.split("?", 1)[0]) from None


def registry_token(registry: str, repository: str) -> str:
    if registry == "docker.io":
        url = "https://auth.docker.io/token?service=registry.docker.io&scope=repository:"
    else:
        url = "https://ghcr.io/token?service=ghcr.io&scope=repository:"
    body, _ = fetch(url + repository + ":pull")
    token = json.loads(body).get("token")
    require(isinstance(token, str) and bool(token), "Registry token unavailable")
    return str(token)


def registry_get(registry: str, repository: str, path: str, accept: str) -> tuple[bytes, str]:
    host = "registry-1.docker.io" if registry == "docker.io" else registry
    headers = {"Authorization": "Bearer " + registry_token(registry, repository), "Accept": accept}
    body, response = fetch(f"https://{host}/v2/{repository}/{path}", headers)
    return body, response.get("docker-content-digest", "")


def digest_of(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def verify_image(image: dict[str, str]) -> None:
    for reference in (image["tag"], image["digest"]):
        body, header = registry_get(
            image["registry"], image["repository"], "manifests/" + reference, MANIFEST_TYPES
        )
        require(
            header == image["digest"] and digest_of(body) == image["digest"],
            f"{image['repository']}:{image['tag']} no longer resolves to the pinned digest",
        )


def chart_manifest(chart: dict[str, str]) -> dict[str, Any]:
    image = {**chart, "tag": chart["version"]}
    verify_image(image)
    body, _ = registry_get(
        chart["registry"], chart["repository"], "manifests/" + chart["digest"], MANIFEST_TYPES
    )
    manifest: dict[str, Any] = json.loads(body)
    layers = [
        layer for layer in manifest.get("layers", []) if layer.get("mediaType") == CHART_LAYER
    ]
    require(
        len(layers) == 1 and layers[0].get("digest") == chart["content_digest"],
        "Chart content digest differs from the pin",
    )
    return manifest


def verify_release_checksums(pins: dict[str, Any]) -> None:
    k3s, helm = pins["k3s"], pins["helm"]
    for arch in ARCHES:
        body, _ = fetch(k3s["source"] + k3s[arch]["checksums"])
        lines = {line.split()[-1]: line.split()[0] for line in body.decode().splitlines() if line}
        require(lines.get(k3s[arch]["asset"]) == k3s[arch]["sha256"], "k3s checksum differs")
        body, _ = fetch(helm["source"] + helm[arch]["asset"] + ".sha256sum")
        require(body.decode().split()[0] == helm[arch]["sha256"], "Helm checksum differs")
    body, _ = fetch(pins["lima_image"]["source"])
    sums = {line.split()[-1]: line.split()[0] for line in body.decode().splitlines() if line}
    for arch in ARCHES:
        image = pins["lima_image"][arch]
        name = image["location"].rsplit("/", 1)[-1]
        require("sha512:" + sums.get(name, "") == image["digest"], "Lima image digest differs")


def verify_pins(pins: dict[str, Any]) -> None:
    check_deploy_files(pins)
    for image in pins["images"].values():
        verify_image(image)
    chart_manifest(pins["chart"])
    verify_release_checksums(pins)


# Owner-only local files


def private_dir() -> Path:
    require(not DATA.is_symlink(), "deploy/.data must not be a symlink")
    DATA.mkdir(mode=0o700, exist_ok=True)
    info = DATA.stat()
    require(info.st_uid == os.getuid(), "deploy/.data is owned by another user")
    if info.st_mode & 0o077:
        DATA.chmod(0o700)
    return DATA


def read_private(path: Path) -> str:
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise GrcLabError(f"Missing {shown(path)}") from None
    require(
        stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o077,
        f"Refusing {shown(path)}: it must be an owner-only (0600) regular file",
    )
    value = path.read_text()
    require(bool(re.fullmatch(r"[A-Za-z0-9_-]{32,}", value)), f"Invalid {path.name}")
    _SECRETS.add(value)
    return value


def write_private(path: Path, content: str | bytes, *, replace: bool = False) -> None:
    private_dir()
    data = content.encode() if isinstance(content, str) else content
    target = path if not replace else path.with_name(path.name + ".tmp")
    if replace:
        target.unlink(missing_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    descriptor = os.open(target, flags, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
    if replace:
        target.replace(path)


def ensure_private(name: str, generate: Callable[[], str]) -> tuple[str, bool]:
    path = private_dir() / name
    if path.exists() or path.is_symlink():
        return read_private(path), False
    value = generate()
    _SECRETS.add(value)
    write_private(path, value)
    return read_private(path), True


# Host and guest commands


def command(
    args: list[str], *, data: bytes | None = None, timeout: int = 300, label: str = ""
) -> str:
    label = label or " ".join(args[:4])
    try:
        done = subprocess.run(args, input=data, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise GrcLabError(f"Command unavailable or timed out: {label}") from None
    if done.returncode:
        detail = redact(done.stderr.decode(errors="replace")).strip().splitlines()[-3:]
        raise GrcLabError(
            f"Command failed: {label}" + ("\n  " + "\n  ".join(detail) if detail else "")
        )
    return done.stdout.decode()


def guest(args: list[str], *, data: bytes | None = None, timeout: int = 300) -> str:
    return command(
        ["limactl", "shell", "--workdir", "/", VM, "sudo", *args],
        data=data,
        timeout=timeout,
        label=f"{VM}: " + " ".join(args[:4]),
    )


def kube(args: list[str], *, data: bytes | None = None, timeout: int = 300) -> str:
    return guest(["k3s", "kubectl", *args], data=data, timeout=timeout)


def helm(args: list[str], *, timeout: int = 900) -> str:
    return guest(["env", "KUBECONFIG=/etc/rancher/k3s/k3s.yaml", "helm", *args], timeout=timeout)


def instance() -> dict[str, Any] | None:
    for line in command(["limactl", "list", "--json"]).splitlines():
        item: dict[str, Any] = json.loads(line) if line.strip() else {}
        if item.get("name") == VM:
            return item
    return None


def verify_instance(item: dict[str, Any] | None, *, running: bool = True) -> dict[str, Any]:
    config: dict[str, Any] = (item or {}).get("config") or {}
    ssh = config.get("ssh") or {}
    containerd = config.get("containerd") or {}
    forwards = config.get("portForwards") or []
    active = [rule for rule in forwards if not rule.get("ignore")]
    single = [PORT, PORT]
    checks = [
        bool(item) and (item or {}).get("name") == VM,
        (config.get("param") or {}).get("owner") == OWNER,
        not config.get("mounts"),
        config.get("vmType") == "vz",
        ssh.get("forwardAgent") is False,
        ssh.get("loadDotSSHPubKeys") is False,
        containerd.get("system") is False and containerd.get("user") is False,
        len(active) == 1
        and active[0].get("guestIP") == "127.0.0.1"
        and active[0].get("hostIP") == "127.0.0.1"
        and active[0].get("guestPortRange") == single
        and active[0].get("hostPortRange") == single,
        any(
            rule.get("ignore") is True
            and rule.get("guestIP") == "0.0.0.0"  # noqa: S104 - matches the ignore-all rule
            and rule.get("guestPortRange") == [1, 65535]
            and rule.get("proto") == "any"
            for rule in forwards
        ),
    ]
    if not all(checks):
        raise GrcLabError(f"Refusing a foreign or unsafe Lima instance named {VM}")
    if running and (item or {}).get("status") != "Running":
        raise GrcLabError(f"The {VM} VM is not running; run `make grc-up`")
    return item or {}


def require_vm(*, running: bool = True) -> dict[str, Any]:
    item = instance()
    require(item is not None, f"No Lima instance named {VM}; run `make grc-up`")
    return verify_instance(item, running=running)


def owned_namespace() -> dict[str, Any] | None:
    raw = kube(["get", "namespace", NAMESPACE, "--ignore-not-found", "-o", "json"])
    if not raw.strip():
        return None
    value: dict[str, Any] = json.loads(raw)
    labels = value.get("metadata", {}).get("labels") or {}
    if labels.get(OWNER_KEY) != OWNER_VALUE:
        raise GrcLabError(f"Refusing namespace {NAMESPACE}: it is not owned by IT GRC")
    return value


def apply(items: list[dict[str, Any]]) -> None:
    document = json.dumps({"apiVersion": "v1", "kind": "List", "items": items})
    kube(
        [
            "apply",
            "--server-side",
            "--force-conflicts",
            "--field-manager",
            FIELD_MANAGER,
            "-f",
            "-",
        ],
        data=document.encode(),
    )


def put_secret(name: str, key: str, value: bytes, public: dict[str, str] | None = None) -> None:
    """Replace one Secret. The secret value travels on stdin only; `public` is not secret."""
    require(bool(re.fullmatch(r"it-grc-[a-z]+", name)), "Invalid Secret name")
    kube(["delete", "secret", name, "--namespace", NAMESPACE, "--ignore-not-found"])
    extra = [f"--from-literal={k}={v}" for k, v in (public or {}).items()]
    kube(
        [
            "create",
            "secret",
            "generic",
            name,
            "--namespace",
            NAMESPACE,
            f"--from-file={key}=/dev/stdin",
            *extra,
        ],
        data=value,
    )
    kube(["label", "secret", name, "--namespace", NAMESPACE, f"{OWNER_KEY}={OWNER_VALUE}"])


# Manifests


def owner_labels(**extra: str) -> dict[str, str]:
    return {OWNER_KEY: OWNER_VALUE, **extra}


def restricted_pod() -> dict[str, Any]:
    return {
        "automountServiceAccountToken": False,
        "enableServiceLinks": False,
        "securityContext": {
            "runAsNonRoot": True,
            "runAsUser": CADDY_UID,
            "runAsGroup": CADDY_UID,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
    }


def restricted_container() -> dict[str, Any]:
    # The Caddy binary carries a file capability. Keeping NET_BIND_SERVICE in the bounding
    # set avoids EPERM on exec; no_new_privs still keeps it out of the non-root process.
    return {
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "capabilities": {"drop": ["ALL"], "add": ["NET_BIND_SERVICE"]},
    }


def cluster_manifests() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = [
        {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": NAMESPACE,
                "labels": owner_labels(
                    **{
                        "pod-security.kubernetes.io/enforce": "restricted",
                        "pod-security.kubernetes.io/enforce-version": "latest",
                    }
                ),
            },
        }
    ]
    for name, (folder, size, _uid) in VOLUMES.items():
        items.append(
            {
                "apiVersion": "v1",
                "kind": "PersistentVolume",
                "metadata": {"name": name, "labels": owner_labels()},
                "spec": {
                    "capacity": {"storage": size},
                    "accessModes": ["ReadWriteOnce"],
                    "persistentVolumeReclaimPolicy": "Retain",
                    "storageClassName": "",
                    "hostPath": {"path": f"{GUEST_DATA}/{folder}", "type": "Directory"},
                    "claimRef": {"namespace": NAMESPACE, "name": name},
                },
            }
        )
    return items


def namespace_manifests(pins: dict[str, Any]) -> list[dict[str, Any]]:
    def meta(name: str) -> dict[str, Any]:
        return {"name": name, "namespace": NAMESPACE, "labels": owner_labels()}

    items: list[dict[str, Any]] = [
        {
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": meta("default"),
            "automountServiceAccountToken": False,
        },
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": meta("it-grc-namespace-only"),
            "spec": {
                "podSelector": {},
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [{"from": [{"podSelector": {}}]}],
                "egress": [
                    {"to": [{"podSelector": {}}]},
                    {
                        "to": [
                            {
                                "namespaceSelector": {
                                    "matchLabels": {"kubernetes.io/metadata.name": "kube-system"}
                                },
                                "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
                            }
                        ],
                        "ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}],
                    },
                ],
            },
        },
        {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": meta(TLS_APP),
            "data": {"Caddyfile": CADDYFILE},
        },
    ]
    for name, (_folder, size, _uid) in VOLUMES.items():
        items.append(
            {
                "apiVersion": "v1",
                "kind": "PersistentVolumeClaim",
                "metadata": meta(name),
                "spec": {
                    "accessModes": ["ReadWriteOnce"],
                    "storageClassName": "",
                    "volumeName": name,
                    "resources": {"requests": {"storage": size}},
                },
            }
        )
    selector = {"app.kubernetes.io/name": TLS_APP}
    checksum = hashlib.sha256(CADDYFILE.encode()).hexdigest()
    items.append(
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": meta(TLS_APP),
            "spec": {
                "replicas": 1,
                "strategy": {"type": "Recreate"},
                "selector": {"matchLabels": selector},
                "template": {
                    "metadata": {
                        "labels": owner_labels(**selector),
                        "annotations": {"it-grc/caddyfile-sha256": checksum},
                    },
                    "spec": {
                        **restricted_pod(),
                        "containers": [
                            {
                                "name": "caddy",
                                "image": image_ref(pins["images"]["caddy"]),
                                "command": ["caddy", "run", "--config", "/etc/caddy/Caddyfile"],
                                "ports": [{"name": "https", "containerPort": PORT}],
                                "securityContext": restricted_container(),
                                "readinessProbe": {"tcpSocket": {"port": PORT}, "periodSeconds": 5},
                                "resources": {
                                    "requests": {"cpu": "10m", "memory": "32Mi"},
                                    "limits": {"memory": "128Mi"},
                                },
                                "volumeMounts": [
                                    {
                                        "name": "caddyfile",
                                        "mountPath": "/etc/caddy",
                                        "readOnly": True,
                                    },
                                    {"name": "data", "mountPath": "/data"},
                                    {"name": "config", "mountPath": "/config"},
                                    {"name": "tmp", "mountPath": "/tmp"},
                                ],
                            }
                        ],
                        "volumes": [
                            {"name": "caddyfile", "configMap": {"name": TLS_APP}},
                            {
                                "name": "data",
                                "persistentVolumeClaim": {"claimName": "it-grc-tls-data"},
                            },
                            {"name": "config", "emptyDir": {"sizeLimit": "16Mi"}},
                            {"name": "tmp", "emptyDir": {"sizeLimit": "16Mi"}},
                        ],
                    },
                },
            },
        }
    )
    return items


def probe_manifest(namespace: str, image: str, script: str) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": PROBE_POD, "namespace": namespace, "labels": owner_labels()},
        "spec": {
            **restricted_pod(),
            "restartPolicy": "Never",
            "containers": [
                {
                    "name": "probe",
                    "image": image,
                    "command": ["sh", "-c", script],
                    "securityContext": restricted_container(),
                    "resources": {"limits": {"memory": "32Mi"}},
                }
            ],
        },
    }


# CISO Assistant over TLS


def https(
    method: str,
    path: str,
    *,
    body: dict[str, Any] | None = None,
    token: str | None = None,
    host: str | None = None,
) -> tuple[int, bytes]:
    context = ssl.create_default_context(cafile=str(DATA / CA_FILE))
    connection = http.client.HTTPSConnection("localhost", PORT, context=context, timeout=30)
    headers = {"Host": host or f"localhost:{PORT}", "Accept": "application/json"}
    payload = None
    if body is not None:
        payload = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Token " + token
    try:
        connection.request(method, path, body=payload, headers=headers)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def wait_ready(timeout: int = 1200) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if https("GET", HEALTH)[0] == 200 and https("GET", "/login")[0] == 200:
                return
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(5)
    raise GrcLabError("CISO Assistant did not become reachable over HTTPS in time")


def login(password: str) -> str | None:
    status, raw = https(
        "POST",
        "/api/_allauth/app/v1/auth/login",
        body={"email": ADMIN_EMAIL, "password": password},
    )
    if status != 200:
        return None
    token = json.loads(raw).get("meta", {}).get("access_token")
    if not isinstance(token, str) or not token:
        return None
    _SECRETS.add(token)
    return token


def logout(token: str) -> None:
    https("POST", "/api/iam/logout/", token=token)


def build_version(token: str) -> str:
    status, raw = https("GET", "/api/build/", token=token)
    require(status == 200, f"/api/build/ answered {status}")
    version = json.loads(raw).get("version")
    return str(version)


# Operations


def ensure_vm() -> None:
    current = instance()
    if current is None:
        say(f"Creating the dedicated {VM} Lima VM (first boot installs pinned k3s and Helm)")
        command(["limactl", "start", "--tty=false", f"--name={VM}", str(PROFILE)], timeout=1800)
    else:
        verify_instance(current, running=False)
        if current.get("status") != "Running":
            say(f"Starting the {VM} VM")
            command(["limactl", "start", "--tty=false", VM], timeout=1200)
    require_vm()


def prepare_storage() -> None:
    guest(["install", "-d", "-m", "0755", "-o", "root", "-g", "root", GUEST_DATA])
    for folder, _size, uid in VOLUMES.values():
        path = f"{GUEST_DATA}/{folder}"
        guest(["install", "-d", "-m", "0700", "-o", str(uid), "-g", str(uid), path])
    for name in VOLUMES:
        raw = kube(["get", "pv", name, "--ignore-not-found", "-o", "json"])
        if not raw.strip():
            continue
        volume = json.loads(raw)
        labels = volume.get("metadata", {}).get("labels") or {}
        require(labels.get(OWNER_KEY) == OWNER_VALUE, f"Refusing foreign PersistentVolume {name}")
        if volume.get("status", {}).get("phase") == "Released":
            # Retain policy: the hostPath data stays; only the stale binding is dropped.
            kube(["delete", "pv", name, "--wait=true"])


def ensure_secrets() -> None:
    django_key, _ = ensure_private(DJANGO_KEY_FILE, lambda: secrets.token_urlsafe(50))
    put_secret(DJANGO_KEY_REF, "django-secret-key", django_key.encode())
    found = kube(
        [
            "get",
            "secret",
            OIDC_KEY_REF,
            "--namespace",
            NAMESPACE,
            "--ignore-not-found",
            "-o",
            "name",
        ]
    )
    if not found.strip():
        # Generated and stored inside the guest; the key never reaches the host.
        script = (
            "set -eu; key=$(openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072);"
            " printf '%s\\n' \"$key\" | k3s kubectl create secret generic"
            f" {OIDC_KEY_REF} --namespace {NAMESPACE}"
            " --from-file=idp-oidc-private-key=/dev/stdin >/dev/null;"
            f" k3s kubectl label secret {OIDC_KEY_REF} --namespace {NAMESPACE}"
            f" {OWNER_KEY}={OWNER_VALUE} >/dev/null"
        )
        guest(["sh", "-c", script])


def stage_release(chart: Path) -> None:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        archive.add(chart, arcname="chart.tgz", recursive=False)
        archive.add(VALUES, arcname="values.yaml", recursive=False)
    stage = guest(["mktemp", "-d", "/tmp/it-grc.XXXXXXXX"]).strip()
    require(bool(re.fullmatch(r"/tmp/it-grc\.[A-Za-z0-9]{8}", stage)), "Invalid staging path")
    try:
        guest(["tar", "-xf", "-", "-C", stage], data=buffer.getvalue())
        staged = guest(["sha256sum", f"{stage}/chart.tgz"]).split()[0]
        require("sha256:" + staged == digest_of(chart.read_bytes()), "Chart changed in transit")
        helm(
            [
                "upgrade",
                "--install",
                RELEASE,
                f"{stage}/chart.tgz",
                "--namespace",
                NAMESPACE,
                "--values",
                f"{stage}/values.yaml",
                "--history-max",
                "5",
                "--timeout",
                "10m",
            ]
        )
    finally:
        guest(["rm", "-rf", "--", stage])


def fetch_chart(pins: dict[str, Any]) -> Path:
    chart = pins["chart"]
    path = private_dir() / f"ciso-assistant-{chart['version']}.tgz"
    if path.is_file() and digest_of(path.read_bytes()) == chart["content_digest"]:
        return path
    body, _ = registry_get(
        chart["registry"], chart["repository"], "blobs/" + chart["content_digest"], "*/*"
    )
    require(digest_of(body) == chart["content_digest"], "Downloaded chart digest differs")
    write_private(path, body, replace=True)
    return path


def export_ca() -> None:
    root = "/data/caddy/pki/authorities/local/root.crt"
    for _ in range(60):
        try:
            pem = kube(
                ["exec", "--namespace", NAMESPACE, f"deployment/{TLS_APP}", "--", "cat", root]
            )
        except GrcLabError:
            time.sleep(2)
            continue
        require(
            pem.startswith("-----BEGIN CERTIFICATE-----") and pem.count("-----BEGIN") == 1,
            "Unexpected CA certificate content",
        )
        write_private(DATA / CA_FILE, pem, replace=True)
        return
    raise GrcLabError("The TLS pod did not create its internal CA in time")


def up(_: argparse.Namespace) -> None:
    pins = load_pins()
    say("Verifying pins against the registries and release checksum files")
    verify_pins(pins)
    chart = fetch_chart(pins)
    ensure_vm()
    if owned_namespace() is None:
        say(f"Creating namespace {NAMESPACE}")
    prepare_storage()
    apply(cluster_manifests())
    apply(namespace_manifests(pins))
    ensure_secrets()
    say(f"Installing chart {pins['chart']['version']} as release {RELEASE}")
    stage_release(chart)
    for name in (TLS_APP, BACKEND, FRONTEND):
        say(f"Waiting for deployment {name}")
        kube(
            ["rollout", "status", f"deployment/{name}", "--namespace", NAMESPACE, "--timeout=900s"],
            timeout=960,
        )
    guest(["systemctl", "enable", FORWARD_UNIT])
    guest(["systemctl", "restart", FORWARD_UNIT])
    export_ca()
    say("Waiting for CISO Assistant over HTTPS (first start runs migrations and loads libraries)")
    wait_ready()
    say(f"CISO Assistant {VERSION} is up at {ORIGIN}")
    say(f"CA certificate for host clients: {shown(DATA / CA_FILE)}")
    if (DATA / ADMIN_CREDENTIAL_FILE).exists():
        say("Administrator password file present; `make grc-admin` creates or re-checks the login")
    else:
        say("Next: `make grc-admin` creates the administrator; nothing secret is printed")


def bootstrap_admin(_: argparse.Namespace) -> None:
    require_vm()
    require(owned_namespace() is not None, "Run `make grc-up` first")
    password, generated = ensure_private(ADMIN_CREDENTIAL_FILE, lambda: secrets.token_urlsafe(24))
    if generated:
        say(f"Generated a new administrator password in {shown(DATA / ADMIN_CREDENTIAL_FILE)}")
    token = login(password)
    created = token is None
    if created:
        put_secret(BOOTSTRAP_REF, "admin-password", password.encode(), {"admin-email": ADMIN_EMAIL})
        say("Restarting the backend so the upstream startup script creates the administrator")
        kube(["rollout", "restart", f"deployment/{BACKEND}", "--namespace", NAMESPACE])
        kube(
            [
                "rollout",
                "status",
                f"deployment/{BACKEND}",
                "--namespace",
                NAMESPACE,
                "--timeout=900s",
            ],
            timeout=960,
        )
        wait_ready()
        token = login(password)
    require(
        token is not None,
        "Login failed: an administrator with another password already exists in the database",
    )
    logout(str(token))
    state = "Created" if created else "Found"
    say(f"{state} the administrator {ADMIN_EMAIL}; login over HTTPS verified")
    say(f"Password file (owner-only): {shown(DATA / ADMIN_CREDENTIAL_FILE)}")


def sync_admin_secret(_: argparse.Namespace) -> None:
    """Copy deploy/.data/admin-password into the bootstrap Secret, on stdin only.

    `it-grc rotate-admin` calls this after a password change. The upstream startup script
    reads the Secret only to create a missing administrator, so a rebuilt database gets the
    current password. The running backend is not restarted."""
    require_vm()
    require(owned_namespace() is not None, "Run `make grc-up` first")
    password = read_private(DATA / ADMIN_CREDENTIAL_FILE)
    put_secret(BOOTSTRAP_REF, "admin-password", password.encode(), {"admin-email": ADMIN_EMAIL})
    raw = kube(["get", "secret", BOOTSTRAP_REF, "--namespace", NAMESPACE, "-o", "json"])
    try:
        stored = base64.b64decode(json.loads(raw)["data"]["admin-password"], validate=True)
    except (ValueError, KeyError, TypeError, binascii.Error):
        raise GrcLabError(f"Secret {BOOTSTRAP_REF} has an unexpected shape") from None
    expected = hashlib.sha256(password.encode()).digest()
    require(
        hmac.compare_digest(hashlib.sha256(stored).digest(), expected),
        f"Secret {BOOTSTRAP_REF} does not hold the password file value",
    )
    say(f"Updated Secret {BOOTSTRAP_REF} from {shown(DATA / ADMIN_CREDENTIAL_FILE)} (verified)")


def run_probe(namespace: str, image: str, script: str) -> str:
    raw = kube(
        ["get", "pod", PROBE_POD, "--namespace", namespace, "--ignore-not-found", "-o", "json"]
    )
    if raw.strip():
        labels = json.loads(raw).get("metadata", {}).get("labels") or {}
        require(
            labels.get(OWNER_KEY) == OWNER_VALUE, f"Refusing foreign pod {namespace}/{PROBE_POD}"
        )
        kube(["delete", "pod", PROBE_POD, "--namespace", namespace, "--wait=true"])
    apply([probe_manifest(namespace, image, script)])
    try:
        for _ in range(60):
            phase = kube(
                [
                    "get",
                    "pod",
                    PROBE_POD,
                    "--namespace",
                    namespace,
                    "-o",
                    "jsonpath={.status.phase}",
                ]
            )
            if phase in {"Succeeded", "Failed"}:
                return kube(["logs", PROBE_POD, "--namespace", namespace])
            time.sleep(2)
        raise GrcLabError(f"Probe pod in {namespace} did not finish")
    finally:
        kube(
            [
                "delete",
                "pod",
                PROBE_POD,
                "--namespace",
                namespace,
                "--ignore-not-found",
                "--wait=false",
            ]
        )


def verify(_: argparse.Namespace) -> None:
    pins = load_pins()
    require_vm()
    require(owned_namespace() is not None, "Run `make grc-up` first")
    password = read_private(DATA / ADMIN_CREDENTIAL_FILE)
    token = login(password)
    require(token is not None, "Administrator login failed; run `make grc-admin`")
    try:
        version = build_version(str(token))
        require(version == VERSION, f"/api/build/ reports {version}, expected {VERSION}")
        say(f"PASS /api/build/ over TLS with the exported CA reports {version}")
        code, raw = https("GET", "/api/iam/current-user/", token=token)
        require(code == 200 and json.loads(raw).get("email") == ADMIN_EMAIL, "current-user failed")
        say("PASS authenticated API call /api/iam/current-user/ returns the administrator")
    finally:
        logout(str(token))
    rejected = https("GET", "/api/build/", host="attacker.example")[0]
    require(rejected in {400, 421}, f"Disallowed Host header answered {rejected}")
    say(f"PASS disallowed Host header at the TLS proxy answers {rejected}")
    image = image_ref(pins["images"]["caddy"])
    # Identical request from both namespaces; only the source differs. The short service
    # name is an allowed Host for the Django check.
    get = "wget -q -T 5 -O /dev/null"
    fqdn = f"http://{BACKEND}.{NAMESPACE}.svc.cluster.local{HEALTH}"
    same = f"{get} --header 'Host: localhost' {fqdn}"
    inside = run_probe(
        NAMESPACE,
        image,
        f"if {same}; then echo reach=ok; else echo reach=fail; fi;"
        f" {get} --header 'Host: attacker.example' http://{BACKEND}{HEALTH} 2>&1"
        " | grep -q ' 400 ' && echo host=400 || echo host=other",
    ).split()
    require("reach=ok" in inside, "Backend unreachable from its own namespace")
    require("host=400" in inside, "Backend accepted a disallowed Host header")
    say("PASS backend reachable inside the namespace; Django rejects a disallowed Host (400)")
    outside = run_probe(
        "default",
        image,
        f'{same} 2>&1 | grep -Eq "can\'t connect|timed out" && echo blocked=yes || echo blocked=no',
    ).split()
    require("blocked=yes" in outside, "NetworkPolicy did not block a pod in namespace default")
    say("PASS NetworkPolicy blocks the same request from a pod in namespace default")
    mounted = kube(
        [
            "get",
            "pods",
            "--namespace",
            NAMESPACE,
            "-o",
            "jsonpath={range .items[*]}{.metadata.name}={.spec.automountServiceAccountToken}"
            "{range .spec.volumes[*]}{.projected.sources[*].serviceAccountToken.path}{end};{end}",
        ]
    )
    require("token" not in mounted, "A pod mounts a service account token")
    say("PASS no pod in the namespace mounts a service account token")


def status(_: argparse.Namespace) -> None:
    item = require_vm(running=False)
    config = item.get("config", {})
    size = f"{config.get('cpus')} CPUs, {config.get('memory')} memory, {config.get('disk')} disk"
    say(f"VM {VM}: {item.get('status')} ({size})")
    if item.get("status") != "Running":
        return
    nodes = kube(["get", "node", VM, "-o", "jsonpath={.status.nodeInfo.kubeletVersion}"])
    say(f"k3s node {VM}: {nodes}")
    if owned_namespace() is None:
        say(f"Namespace {NAMESPACE}: absent")
        return
    releases = json.loads(helm(["list", "--namespace", NAMESPACE, "-o", "json"], timeout=120))
    for release in releases:
        state = f"{release['status']}, {release['chart']}, revision {release['revision']}"
        say(f"Helm release {release['name']}: {state}")
    pods = kube(
        [
            "get",
            "pods",
            "--namespace",
            NAMESPACE,
            "-o",
            "jsonpath={range .items[*]}{.metadata.name} {.status.phase}"
            ' restarts={.status.containerStatuses[*].restartCount}{"\\n"}{end}',
        ]
    )
    for line in pods.splitlines():
        say(f"  pod {line}")
    memory = guest(["free", "-m"]).splitlines()[1].split()
    say(f"Guest memory: {memory[2]} MiB used of {memory[1]} MiB, {memory[6]} MiB available")
    disk = guest(["df", "-h", "--output=used,size", "/"]).splitlines()[1].split()
    data = guest(["du", "-sh", GUEST_DATA]).split()[0]
    say(f"Guest disk: {disk[0]} used of {disk[1]}; application data {data}")
    if (DATA / CA_FILE).exists():
        try:
            code = https("GET", "/login")[0]
            say(f"{ORIGIN}: HTTPS {code} (CA {shown(DATA / CA_FILE)})")
        except (OSError, http.client.HTTPException):
            say(f"{ORIGIN}: not reachable")
    path = DATA / ADMIN_CREDENTIAL_FILE
    say(f"Administrator password file: {shown(path)} ({'present' if path.exists() else 'absent'})")


def down(_: argparse.Namespace) -> None:
    require_vm()
    if owned_namespace() is not None:
        if RELEASE in helm(["list", "--namespace", NAMESPACE, "-q"], timeout=120).split():
            helm(["uninstall", RELEASE, "--namespace", NAMESPACE, "--wait", "--timeout", "5m"])
        kube(["delete", "namespace", NAMESPACE, "--wait=true", "--timeout=300s"], timeout=360)
    guest(["systemctl", "disable", "--now", FORWARD_UNIT])
    say(f"Removed release {RELEASE} and namespace {NAMESPACE}; VM data under {GUEST_DATA} is kept")


def stop(_: argparse.Namespace) -> None:
    item = require_vm(running=False)
    if item.get("status") == "Stopped":
        say(f"The {VM} VM is already stopped")
        return
    command(["limactl", "stop", VM], timeout=600)
    say(f"Stopped the {VM} VM; CISO Assistant stays installed and starts again with `make grc-up`")


def destroy(args: argparse.Namespace) -> None:
    require(bool(args.yes), f"Refusing to delete the {VM} VM without --yes")
    item = require_vm(running=False)
    if item.get("status") == "Running":
        command(["limactl", "stop", VM], timeout=600)
    command(["limactl", "delete", VM], timeout=600)
    say(f"Deleted the {VM} VM and its data; local files under deploy/.data are kept")


OPERATIONS: dict[str, Callable[[argparse.Namespace], None]] = {
    "up": up,
    "status": status,
    "bootstrap-admin": bootstrap_admin,
    "sync-admin-secret": sync_admin_secret,
    "verify": verify,
    "down": down,
    "stop": stop,
    "destroy": destroy,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Dedicated it-grc Lima VM for CISO Assistant CE")
    commands = parser.add_subparsers(dest="operation", required=True)
    for name in OPERATIONS:
        sub = commands.add_parser(name)
        if name == "destroy":
            sub.add_argument("--yes", action="store_true", help="confirm deleting the VM")
    args = parser.parse_args(argv)
    try:
        OPERATIONS[args.operation](args)
    except GrcLabError as error:
        print("it-grc: " + redact(str(error)), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
