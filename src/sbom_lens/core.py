from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import requests


class Cancelled(RuntimeError):
    pass


@dataclass(frozen=True)
class Component:
    name: str
    version: str
    kind: str
    purl: str = ""
    locations: tuple[str, ...] = ()


@dataclass
class SBOM:
    path: Path
    name: str
    version: str
    components: list[Component]
    format: str


def load_sbom(path: Path) -> SBOM:
    data = json.loads(path.read_text())
    if data.get("bomFormat") == "CycloneDX":
        if not isinstance(data.get("components", []), list):
            raise ValueError("Invalid CycloneDX components")
        root = data.get("metadata", {}).get("component", {})
        components = []
        def walk(items):
            for item in items:
                components.append(Component(item.get("name", ""), item.get("version", ""),
                                            item.get("type", ""), item.get("purl", "")))
                walk(item.get("components", []))
        walk(data.get("components", []))
        return SBOM(path, root.get("name", path.stem), root.get("version", ""), components, "cyclonedx")
    if isinstance(data.get("artifacts"), list) and isinstance(data.get("source"), dict):
        source = data["source"]
        components = [Component(a.get("name", ""), a.get("version", ""), a.get("type", ""),
                                a.get("purl", ""), tuple(l.get("path", "") for l in a.get("locations", [])))
                      for a in data["artifacts"]]
        return SBOM(path, source.get("name", path.stem), source.get("version", ""), components, "syft")
    raise ValueError("Unsupported SBOM. Use CycloneDX JSON or Syft JSON (not SPDX, HTML, or an archive).")


def search(components: list[Component], text: str, exact: bool = True) -> list[Component]:
    value = text.strip().casefold()
    if not value:
        return components
    if exact:
        return [c for c in components if c.name.casefold() == value]
    return [c for c in components if value in f"{c.name} {c.version} {c.purl}".casefold()]


def validate_ref(ref: str, package=False):
    if not ref or ref.startswith("-") or any(c.isspace() for c in ref) or any(c in ref for c in "\x00\n\r"):
        raise ValueError("Enter a registry reference, not a shell command or URL with spaces")
    if package and not ref.startswith("oci://"):
        raise ValueError("Zarf/UDS package references must start with oci://")
    if not package and "://" in ref:
        raise ValueError("Use registry/image:tag or registry/image@sha256:digest, without a URL scheme")


def run(args: list[str], cancel: threading.Event, log, timeout=1800) -> str:
    if not shutil.which(args[0]):
        raise RuntimeError(f"Missing {args[0]}. Install Zarf and put it on PATH; see README.")
    if cancel.is_set():
        raise Cancelled("Cancelled")
    log("Running " + " ".join(args[:5]))
    # Temporary files avoid pipe deadlocks and keep command output out of process memory.
    import tempfile
    with tempfile.TemporaryFile(mode="w+") as out, tempfile.TemporaryFile(mode="w+") as err:
        process = subprocess.Popen(args, stdout=out, stderr=err)  # no shell
        deadline = time.monotonic() + timeout
        try:
            while process.poll() is None:
                if cancel.wait(.2):
                    raise Cancelled("Cancelled; already accepted server jobs are not rolled back")
                if time.monotonic() > deadline:
                    raise TimeoutError("Command exceeded 30 minutes")
            out.seek(0)
            err.seek(0)
            output, errors = out.read(), err.read()
            if errors.strip():
                log(errors[-6000:])
            if process.returncode:
                raise RuntimeError(errors[-3000:] or output[-3000:] or "Command failed")
            return output
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def acquire(kind: str, reference: str, architecture: str, directory: Path,
            cancel: threading.Event, log, identity="", issuer="") -> list[SBOM]:
    if architecture not in ("amd64", "arm64"):
        raise ValueError("Architecture must be amd64 or arm64")
    if kind == "file":
        return [load_sbom(Path(reference).expanduser())]
    validate_ref(reference, package=kind == "package")
    if kind == "image":
        log("SCANNING IMAGE: pulling/cataloging may take several minutes with little output. Ctrl+X cancels.")
        output = directory / "image.syft.json"
        run(["zarf", "tools", "sbom", "scan", "registry:" + reference,
             "--platform", "linux/" + architecture, "-o", f"syft-json={output}"], cancel, log)
        return [load_sbom(output)]
    if kind != "package":
        raise ValueError("Unknown source type")
    if bool(identity) != bool(issuer):
        raise ValueError("Set both SBOM_LENS_CERT_IDENTITY and SBOM_LENS_CERT_ISSUER for keyless verification")
    verification = (["--certificate-identity-regexp", identity, "--certificate-oidc-issuer", issuer,
                     "--verify=always"] if identity else [])
    log("EXTRACTING published SBOMs, not scanning images. Review Zarf signature warnings.")
    run(["zarf", "package", "inspect", "sbom", reference, "-a", architecture,
         "--no-color", "--output", str(directory), *verification], cancel, log)
    results = []
    for path in sorted(directory.rglob("*.json")):
        if cancel.is_set():
            raise Cancelled("Cancelled")
        try:
            sbom = load_sbom(path)
            source = json.loads(path.read_text()).get("source", {})
            if source.get("type") not in (None, "image"):
                continue
            results.append(sbom)
        except (ValueError, KeyError):
            continue
    if not results:
        raise ValueError("No supported JSON SBOMs found in package; no substitute image was scanned")
    return results


class DependencyTrack:
    def __init__(self, url: str, api_key: str):
        url = url.rstrip("/")
        parsed = urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Use a Dependency-Track API URL without credentials, query, or fragment")
        if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
            raise ValueError("Use HTTPS for remote Dependency-Track servers")
        if not api_key:
            raise ValueError("Set SBOM_LENS_DT_API_KEY to a Dependency-Track API key")
        self.url = url
        self.session = requests.Session()
        self.session.headers["X-Api-Key"] = api_key

    def close(self):
        self.session.close()

    def request(self, method, path, **kwargs):
        response = self.session.request(method, self.url + path, timeout=120, allow_redirects=False, **kwargs)
        if not 200 <= response.status_code < 300:
            raise RuntimeError(f"Dependency-Track HTTP {response.status_code}; check URL, permissions and API key")
        return response.json()

    def upload(self, sbom: SBOM, name: str, version: str, directory: Path, cancel, log) -> str:
        if not name.strip() or not version.strip():
            raise ValueError("Project name and version are required")
        path = sbom.path
        if sbom.format != "cyclonedx":
            path = directory / "upload.cdx.json"
            run(["zarf", "tools", "sbom", "convert", str(sbom.path), "-o", f"cyclonedx-json@1.6={path}"], cancel, log)
        if cancel.is_set():
            raise Cancelled("Cancelled")
        with path.open("rb") as file:
            result = self.request("POST", "/api/v1/bom", data={"projectName": name, "projectVersion": version,
                "autoCreate": "true"}, files={"bom": (path.name, file, "application/json")})
        project = result.get("projectUuid")
        if not project:
            project = self.request("GET", "/api/v1/project/lookup", params={"name": name, "version": version})["uuid"]
        log("Upload accepted. Ingestion and vulnerability analysis run asynchronously; zero findings are not an all-clear.")
        return project

    def exact_component(self, project: str, name: str, cancel) -> list[dict]:
        found, page = [], 1
        while True:
            if cancel.is_set():
                raise Cancelled("Cancelled")
            rows = self.request("GET", f"/api/v1/component/project/{project}",
                                params={"pageSize": 100, "pageNumber": page})
            if not isinstance(rows, list):
                raise ValueError("Unexpected component response")
            found.extend(c for c in rows if c.get("name", "").casefold() == name.strip().casefold())
            if len(rows) < 100:
                return found
            page += 1
