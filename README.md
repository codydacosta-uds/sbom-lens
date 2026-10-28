# SBOM Lens

A small, local-first terminal app for answering **“which version of this component is inside that image?”**

Load an SBOM, search `node`, and see the exact Node version—not thousands of `node_modules` paths. Optionally upload to your own [OWASP Dependency-Track](https://dependencytrack.org/) server and open exact component matches across every page.

Free and MIT licensed. No hosted account, proprietary feed, organization-specific configuration, or paid integration is required.

## Quick start

Requires **Python 3.11+**. Linux, macOS and Windows are supported by the dependencies; local testing is on macOS and CI exercises all three.

```bash
git clone https://github.com/codydacosta-uds/sbom-lens.git
cd sbom-lens
python -m pip install pipx
pipx install .
sbom-lens
```

Alternatively use a virtual environment:

```bash
python -m venv .venv
# macOS/Linux:
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install .
sbom-lens
```

Local **CycloneDX JSON** and **Syft JSON** files work immediately. Install [Zarf](https://docs.zarf.dev/getting-started/install/) and put `zarf` on PATH to scan images, extract package SBOMs, or convert Syft JSON for upload. Zarf includes the SBOM tooling; no container runtime is needed just to scan a registry image.

## Three inputs, one workflow

| Source | Reference | What happens |
|---|---|---|
| Local SBOM | `/path/to/sbom.json` | Reads the existing JSON locally |
| Container image | `registry.example/team/app:1.2.3` | Downloads/catalogs the image and generates a fresh SBOM |
| Zarf / UDS package | `oci://registry.example/team/package:1.2.3` | Extracts publisher-provided JSON SBOMs; choose an image in the picker |

1. Choose source, enter its reference, choose `amd64` or `arm64`, then **Load SBOM**.
2. Select the image SBOM if there are several.
3. Type `node`, `brotli4j`, or another component name. **Exact name is on by default**, case-insensitive. Uncheck it for substring/name/version/package-URL search.
4. Select a component and press Enter to show its package URL and any recorded file locations.

Image scans can take minutes with little diagnostic output. The log explicitly says **SCANNING** vs **EXTRACTING**. Ctrl+X cancels the local command. Already accepted server-side jobs are not rolled back; in-flight HTTP requests may finish before cancellation takes effect.

SBOMs are kept in a private temporary working directory and removed on normal exit. The original local file is never modified. No reports, release comparisons, organization-specific overrides, or exports are generated.

### Private registries / verification

Run registry login tools locally before launching. Zarf uses its normal host registry credential lookup; credentials are not uploaded to Dependency-Track. Cloud registry credentials may expire and require reauthentication.

Image tags can move: use `registry/image@sha256:...` or digest-qualified package references for reproducibility. Package extraction uses Zarf's default verification behavior and displays its warnings. For trusted keyless package signatures, set **both**:

```bash
export SBOM_LENS_CERT_IDENTITY='^https://github\.com/TRUSTED-ORG/REPO/.*$'
export SBOM_LENS_CERT_ISSUER='https://token.actions.githubusercontent.com'
```

These values must come from a publisher you independently trust. When configured, verification is required and failures are not bypassed. Extracted SBOM inventory is not proof of what a deployment actually runs; pass the package/image that your deployment uses.

## Optional: Dependency-Track

**Browsing and exact search do not need Dependency-Track.** It adds asynchronous vulnerability analysis using the feeds you configure on your server.

Use an existing server, or start the included local-only Docker Compose stack:

```bash
# Choose a strong local database password. Do not commit .env.
printf 'DT_DB_PASSWORD=replace-with-a-long-random-password\n' > .env
docker compose up -d
```

Open http://localhost:8081, sign in with the new installation's `admin` / `admin`, and immediately change the password. If ports 8080/8081 are already occupied, use that existing installation or change the Compose ports and matching environment settings.

In **Administration → Access Management → Teams**, create a dedicated team/API key with at least `BOM_UPLOAD`, `PROJECT_CREATION_UPLOAD`, `VIEW_PORTFOLIO`, and `VIEW_VULNERABILITY` (project-creation permission names can vary by version). If access control is enabled, grant the team access to your projects. Do not use or share an administrator token unnecessarily.

```bash
export SBOM_LENS_DT_URL=http://localhost:8080
export SBOM_LENS_DT_UI_URL=http://localhost:8081
# Set SBOM_LENS_DT_API_KEY in your environment via your password manager or shell.
sbom-lens
```

- **U** (outside an input): upload the selected SBOM. Project name/version default to SBOM metadata. Override with `SBOM_LENS_PROJECT_NAME` and `SBOM_LENS_PROJECT_VERSION` when metadata is absent or needs a clearer label.
- The project page opens in your default browser. Log in there normally; API keys are never placed in browser URLs.
- Wait for ingestion, enter `node` in the search box, focus the component table, then press **D**. The tool retrieves **every page** from the project, matches the exact component name, logs its version/direct link, and opens it when only one match exists.
- To look up an existing project instead, set `SBOM_LENS_DT_PROJECT` to its project UUID. Loading/changing a local SBOM clears the tool's previous uploaded-project association.
- Remote APIs must use **HTTPS**. API redirects are rejected to avoid forwarding credentials elsewhere. Environment credentials are not logged or committed.

### Vulnerability sources and limits

Enable/configure **NVD**, **OSV**, and the **Internal analyzer** in your Dependency-Track installation. Let the initial feed sync complete before judging results. OSV ecosystem selection determines coverage. An optional free Trivy server/analyzer can add OS/library coverage; it is not bundled or enabled automatically by this app. Other integrations may need API keys or subscriptions.

**An SBOM is inventory, not a clean bill of health.** The app does not itself match CVEs or claim to scan vulnerabilities. A generic binary such as Node may contain vulnerable native libraries that feed identifiers do not associate automatically. Missing or zero findings do not establish safety. Review vendor advisories and whether untrusted input can reach the vulnerable functionality. The tool never manually assigns a CVE to make it appear detected.

## Settings

| Environment variable | Meaning |
|---|---|
| `SBOM_LENS_DT_URL` | API origin; default `http://localhost:8080` |
| `SBOM_LENS_DT_UI_URL` | Browser UI; default `http://localhost:8081` |
| `SBOM_LENS_DT_API_KEY` | Team API key; needed only for tracker actions |
| `SBOM_LENS_DT_PROJECT` | Existing project UUID for exact lookup |
| `SBOM_LENS_PROJECT_NAME` | Override upload project name |
| `SBOM_LENS_PROJECT_VERSION` | Override upload version |
| `SBOM_LENS_CERT_IDENTITY` | Trusted keyless package signer identity regex |
| `SBOM_LENS_CERT_ISSUER` | Trusted keyless package OIDC issuer |

Quit with Q outside an input; while busy Q requests cancellation first. Use Tab to move focus. No hardcoded home directory, browser, registry, GitHub authentication, or company repository is required.

## Development

```bash
python -m pip install -e '.[test]'
python -m pytest -q
```

Tests exercise SBOM parsing, exact search, API pagination, credential transport safeguards, and the terminal load/search flow without requiring live registries. Registry scans and feed completeness depend on external tools/services and are not guaranteed by these tests.
