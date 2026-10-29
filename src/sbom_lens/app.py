from __future__ import annotations

import os
import tempfile
import threading
import webbrowser
from pathlib import Path

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.widgets import Button, Checkbox, DataTable, Footer, Header, Input, RichLog, Select, Static

from .core import Cancelled, DependencyTrack, acquire, search


class Lens(App):
    TITLE = "SBOM Lens"
    SUB_TITLE = "Exact component search · local-first · optional vulnerability tracking"
    CSS = """
    Screen { padding: 0 1; }
    Input, Select { height: 3; }
    #components { height: 1fr; min-height: 5; }
    #log { height: 6; border: round $primary; }
    #notice { height: 2; color: $warning; }
    Button { min-width: 16; }
    #source-label { height: 1; }
    """
    BINDINGS = [("q", "safe_quit", "Quit"), ("ctrl+x", "cancel", "Cancel"),
                ("u", "upload", "Upload"), ("d", "lookup", "Find in tracker")]

    def __init__(self):
        super().__init__()
        self.workspace = tempfile.TemporaryDirectory(prefix="sbom-lens-")
        self.sboms = []
        self.current = None
        self.cancel = threading.Event()
        self.busy = False
        self.project = os.environ.get("SBOM_LENS_DT_PROJECT", "")
        self.filtered_components = []

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Source → reference → Load. Select an extracted SBOM, then search for a component.", id="source-label")
        yield Select([("Container image (scan)", "image"), ("Zarf / UDS package (extract)", "package"),
                      ("Local SBOM JSON file", "file")], value="file", allow_blank=False, id="source")
        yield Input(placeholder="/path/to/sbom.json | registry/image:tag | oci://registry/package:version", id="reference")
        yield Select([("linux/amd64", "amd64"), ("linux/arm64", "arm64")], value="amd64", allow_blank=False, id="arch")
        yield Button("Load SBOM", id="load", variant="primary")
        yield Select([], prompt="Choose an SBOM from this source", id="sbom")
        yield Input(placeholder="Component name, e.g. node, brotli4j, openssl (blank shows all)", id="search")
        yield Checkbox("Exact component name (avoids node_modules matches)", value=True, id="exact")
        yield Static("SBOM inventory is not a vulnerability scan. Missing findings do not prove safety.", id="notice")
        yield DataTable(id="components", cursor_type="row")
        yield RichLog(id="log", wrap=True, markup=False)
        yield Footer()

    def on_mount(self):
        table = self.query_one(DataTable)
        table.add_columns("Component", "Version", "Type", "Package URL")
        self.query_one("#log", RichLog).write(Text(
            "Optional Dependency-Track: set SBOM_LENS_DT_URL, SBOM_LENS_DT_API_KEY and SBOM_LENS_DT_UI_URL. U uploads; D finds the exact search name across every project page."))

    def on_unmount(self):
        self.workspace.cleanup()

    def log_line(self, text):
        self.call_from_thread(self.query_one("#log", RichLog).write, Text(text))

    def set_busy(self, value):
        self.busy = value
        for id in ("load", "source", "reference", "arch", "sbom"):
            self.query_one("#" + id).disabled = value

    @on(Button.Pressed, "#load")
    def load(self):
        if not self.busy:
            self.cancel = threading.Event()
            self.set_busy(True)
            self.acquire_worker(str(self.query_one("#source", Select).value),
                self.query_one("#reference", Input).value.strip(), str(self.query_one("#arch", Select).value))

    @work(thread=True)
    def acquire_worker(self, kind, reference, architecture):
        try:
            directory = Path(tempfile.mkdtemp(dir=self.workspace.name))
            results = acquire(kind, reference, architecture, directory, self.cancel, self.log_line,
                os.environ.get("SBOM_LENS_CERT_IDENTITY", ""), os.environ.get("SBOM_LENS_CERT_ISSUER", ""))
            self.call_from_thread(self.loaded, results)
        except Exception as exc:
            self.log_line(f"ERROR: {exc}")
        finally:
            self.call_from_thread(self.set_busy, False)

    def loaded(self, results):
        self.sboms = results
        # Never reuse a previous project's ID after changing source.
        self.project = ""
        self.query_one("#sbom", Select).set_options([
            (f"{s.name} {s.version} · {len(s.components)} components", str(i)) for i, s in enumerate(results)])
        self.query_one("#sbom", Select).value = "0"

    @on(Select.Changed, "#sbom")
    def selected(self, event):
        if event.value is not Select.BLANK:
            self.current = self.sboms[int(event.value)]
            self.project = ""
            self.render_components()

    @on(Input.Changed, "#search")
    @on(Checkbox.Changed, "#exact")
    def render_components(self):
        if not self.current:
            return
        table = self.query_one(DataTable)
        table.clear()
        self.filtered_components = search(self.current.components, self.query_one("#search", Input).value,
                              self.query_one("#exact", Checkbox).value)
        for c in self.filtered_components:
            table.add_row(Text(c.name), Text(c.version), Text(c.kind), Text(c.purl))
        self.query_one("#notice", Static).update(
            f"{len(self.filtered_components)} matches / {len(self.current.components)} components. "
            "Inventory only; bundled libraries and vulnerability matching can have gaps.")

    @on(DataTable.RowSelected)
    def details(self, event):
        if event.cursor_row < len(self.filtered_components):
            c = self.filtered_components[event.cursor_row]
            self.query_one("#log", RichLog).write(Text(
                f"{c.name} @ {c.version}\n{c.purl}\n" + "\n".join(c.locations or ("No file locations recorded by this SBOM format.",))))

    def client(self):
        return DependencyTrack(os.environ.get("SBOM_LENS_DT_URL", "http://localhost:8080"),
                               os.environ.get("SBOM_LENS_DT_API_KEY", ""))

    def action_upload(self):
        if self.current and not self.busy:
            self.cancel = threading.Event()
            self.set_busy(True)
            self.tracker_worker("upload", self.query_one("#search", Input).value)

    def action_lookup(self):
        if not self.busy:
            self.cancel = threading.Event()
            self.set_busy(True)
            self.tracker_worker("lookup", self.query_one("#search", Input).value)

    @work(thread=True)
    def tracker_worker(self, action, name):
        client = None
        try:
            client = self.client()
            ui = os.environ.get("SBOM_LENS_DT_UI_URL", "http://localhost:8081").rstrip("/")
            # Validate the UI origin too; never attach API keys to browser URLs.
            from urllib.parse import urlsplit
            parsed = urlsplit(ui)
            if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise ValueError("Invalid Dependency-Track UI URL")
            if action == "upload":
                sbom = self.current
                project = client.upload(sbom, os.environ.get("SBOM_LENS_PROJECT_NAME") or sbom.name,
                    os.environ.get("SBOM_LENS_PROJECT_VERSION") or sbom.version,
                    Path(tempfile.mkdtemp(dir=self.workspace.name)), self.cancel, self.log_line)
                self.project = project
                url = f"{ui}/projects/{project}/components"
                self.log_line("Open: " + url)
                webbrowser.open(url)
            else:
                project = self.project or os.environ.get("SBOM_LENS_DT_PROJECT", "")
                if not project or not name.strip():
                    raise ValueError("Upload first (or set SBOM_LENS_DT_PROJECT) and enter an exact component name")
                matches = client.exact_component(project, name, self.cancel)
                for c in matches:
                    self.log_line(f"EXACT MATCH: {c['name']} @ {c.get('version', '?')} — {ui}/components/{c['uuid']}")
                if not matches:
                    self.log_line("No exact component match. If just uploaded, wait for ingestion before retrying.")
                elif len(matches) == 1:
                    webbrowser.open(f"{ui}/components/{matches[0]['uuid']}")
        except Exception as exc:
            self.log_line(f"ERROR: {exc}")
        finally:
            if client:
                client.close()
            self.call_from_thread(self.set_busy, False)

    def action_cancel(self):
        self.cancel.set()
        self.query_one("#log", RichLog).write(Text("Cancellation requested; an in-flight HTTP request may finish first."))

    def action_safe_quit(self):
        if self.busy:
            self.action_cancel()
        else:
            self.exit()


def main():
    Lens().run()


if __name__ == "__main__":
    main()
