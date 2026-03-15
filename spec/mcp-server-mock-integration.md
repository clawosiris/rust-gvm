# openvas-mcp-server: Mock Server Integration Test Spec

## 1. Overview

Add integration tests to [openvas-mcp-server](https://github.com/clawosiris/openvas-mcp-server) that exercise the full service layer against [gvm-mock-server](https://github.com/clawosiris/rust-gvm) instead of Python `MagicMock` objects. This validates that the MCP server's GMP client code works end-to-end against a real GMP-speaking server — without requiring a live Greenbone instance.

### Why

The current unit tests use `unittest.mock.MagicMock` to simulate `GvmClient.execute()`. This means:

1. **Response XML is never validated** — tests build `Element` trees manually; they don't prove python-gvm can parse the responses
2. **python-gvm's XML generation is untested** — the actual GMP XML commands are never sent over a wire
3. **Version negotiation is untested** — the two-connection flow (get_version probe → reconnect → authenticate) is mocked out
4. **Connection lifecycle is untested** — connect/disconnect/reconnect never happens
5. **Filter strings are untested** — `filter_string` parameters are passed to mocks, never parsed

With gvm-mock-server, each service method exercises the full stack:
```
Service.method() → GvmClient.execute() → python-gvm GMP → Unix socket → mock server → response XML → python-gvm parse → Service result
```

### Scope

- **In scope:** Service-layer integration tests, CI workflow, pytest fixtures
- **Out of scope:** MCP tool tests (those wrap services and are already tested), CLI tests, changing existing unit tests

---

## 2. Architecture

### Test Flow

```
┌──────────────────────────────────────┐
│         pytest (integration)          │
│                                       │
│  1. Download gvm-mock-server binary   │
│  2. Start on temp Unix socket         │
│  3. Create GvmClient(LocalClient)     │
│  4. Create Service(client)            │
│  5. Call service methods              │
│  6. Assert results                    │
│  7. Shutdown server                   │
└──────────────┬───────────────────────┘
               │ Unix socket
┌──────────────▼───────────────────────┐
│      gvm-mock-server (binary)         │
│      --mode stateful                  │
│      --version 22.5                   │
│      --socket /tmp/xxx/mock.sock      │
└──────────────────────────────────────┘
```

### Binary Acquisition

The CI workflow downloads the pre-built `gvm-mock-server` binary from the [rust-gvm nightly release](https://github.com/clawosiris/rust-gvm/releases/tag/nightly):

```yaml
- name: Download mock server
  run: |
    curl -sL https://github.com/clawosiris/rust-gvm/releases/download/nightly/gvm-mock-server-linux-amd64-musl.tar.gz \
      | tar xz -C /usr/local/bin/
    chmod +x /usr/local/bin/gvm-mock-server
```

The musl (statically linked) build ensures no shared library dependencies.

For local development, developers can either:
- Build from source: `cargo build -p gvm-mock-server` in the rust-gvm repo
- Download a nightly binary
- Skip integration tests: `pytest -m "not integration"`

---

## 3. Pytest Fixtures

### `conftest.py` additions (`tests/integration/conftest.py`)

```python
import os
import signal
import subprocess
import tempfile
import time
from pathlib import Path

import pytest
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import GMP
from gvm.transforms import EtreeCheckCommandTransform

from src.infrastructure.client.local import LocalClient
from src.infrastructure.config import ConnectionStyle, GvmConfig


MOCK_SERVER_BIN = os.environ.get(
    "GVM_MOCK_SERVER_BIN",
    "gvm-mock-server",  # expects it on PATH
)


@pytest.fixture(scope="session")
def mock_server():
    """Start gvm-mock-server for the test session."""
    tmp_dir = tempfile.mkdtemp(prefix="gvm-mock-")
    socket_path = os.path.join(tmp_dir, "mock.sock")

    proc = subprocess.Popen(
        [MOCK_SERVER_BIN, "--mode", "stateful", "--version", "22.5",
         "--socket", socket_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for socket
    deadline = time.time() + 10
    while time.time() < deadline:
        if os.path.exists(socket_path):
            break
        if proc.poll() is not None:
            raise RuntimeError(f"Mock server exited: {proc.stderr.read()}")
        time.sleep(0.05)
    else:
        proc.kill()
        raise TimeoutError("Mock server socket not created")

    yield {"process": proc, "socket_path": socket_path}

    proc.send_signal(signal.SIGINT)
    try:
        proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate(timeout=5)


@pytest.fixture(scope="session")
def mock_config(mock_server):
    """GvmConfig pointing at the mock server."""
    return GvmConfig(
        style=ConnectionStyle.LOCAL,
        socket_path=mock_server["socket_path"],
        gmp_username="admin",
        gmp_password="admin",
        timeout=30,
    )


@pytest.fixture(scope="session")
def mock_client(mock_config):
    """LocalClient connected to the mock server."""
    client = LocalClient(mock_config)
    yield client
    client.disconnect()
```

### Marker

```python
# conftest.py or pyproject.toml
[tool.pytest.ini_options]
markers = [
    "integration: tests requiring gvm-mock-server binary",
]
```

---

## 4. Test Plan

### 4.1 System Service

```python
@pytest.mark.integration
class TestSystemServiceIntegration:
    def test_get_version(self, mock_client):
        """Version negotiation returns 22.5."""
        result = mock_client.execute(lambda gmp: gmp.get_version())
        assert result.findtext("version") == "22.5"
```

### 4.2 Target Service

```python
@pytest.mark.integration
class TestTargetServiceIntegration:
    def test_create_and_get_target(self, mock_client):
        """Create target, then retrieve it."""
        service = TargetService(mock_client)
        created = service.create(name="Integration Target", hosts=["10.0.0.0/24"])
        target_id = created.get("id")
        assert target_id

        target = service.get(target_id)
        assert target is not None

    def test_list_targets(self, mock_client):
        """List targets returns previously created targets."""
        service = TargetService(mock_client)
        targets = service.list()
        assert len(targets) > 0

    def test_modify_target(self, mock_client):
        """Modify target name."""
        service = TargetService(mock_client)
        created = service.create(name="Before", hosts=["10.0.0.1"])
        target_id = created.get("id")
        service.modify(target_id, name="After")

    def test_delete_target(self, mock_client):
        """Delete target (to trash)."""
        service = TargetService(mock_client)
        created = service.create(name="Disposable", hosts=["10.0.0.2"])
        target_id = created.get("id")
        service.delete(target_id)

    def test_clone_target(self, mock_client):
        """Clone target returns new ID."""
        service = TargetService(mock_client)
        created = service.create(name="Cloneable", hosts=["10.0.0.3"])
        target_id = created.get("id")
        cloned = service.clone(target_id)
        assert cloned.get("id") != target_id
```

### 4.3 Task Service

```python
@pytest.mark.integration
class TestTaskServiceIntegration:
    def test_task_lifecycle(self, mock_client):
        """Full lifecycle: create → start → stop → get status."""
        target_svc = TargetService(mock_client)
        task_svc = TaskService(mock_client)

        # Setup
        target = target_svc.create(name="Task Target", hosts=["10.0.1.0/24"])
        target_id = target.get("id")

        # Create task (using well-known config/scanner UUIDs)
        task = task_svc.create(TaskCreateRequest(
            name="Integration Task",
            target_id=target_id,
            config_id="daba56c8-73ec-11df-a475-002264764cea",
            scanner_id="08b69003-5fc2-4037-a479-93b440211c73",
        ))
        task_id = task.get("id")
        assert task_id

        # Start
        start_resp = task_svc.start(task_id)
        report_id = start_resp.findtext("report_id")
        assert report_id

        # Check running
        status = task_svc.get(task_id)
        assert status.findtext("status") == "Running"

        # Stop
        task_svc.stop(task_id)
        status = task_svc.get(task_id)
        assert status.findtext("status") == "Stopped"

    def test_list_tasks(self, mock_client):
        """List tasks returns results."""
        service = TaskService(mock_client)
        tasks = service.list()
        assert isinstance(tasks, list) or tasks is not None

    def test_clone_task(self, mock_client):
        """Clone creates a new task."""
        # Uses previously created task
        service = TaskService(mock_client)
        tasks = service.list()
        if tasks:
            original_id = tasks[0].get("id")
            cloned = service.clone(original_id)
            assert cloned.get("id") != original_id
```

### 4.4 Notes Service

```python
@pytest.mark.integration
class TestNotesServiceIntegration:
    def test_note_crud(self, mock_client):
        """Create, get, modify, delete note."""
        service = NotesService(mock_client)

        created = service.create(text="Test note", nvt_oid="1.3.6.1.4.1.25623.1.0.12345")
        note_id = created.get("id")
        assert note_id

        notes = service.list()
        assert any(n.get("id") == note_id for n in notes)

        service.modify(note_id, text="Updated note")
        service.delete(note_id)
```

### 4.5 Overrides Service

```python
@pytest.mark.integration
class TestOverridesServiceIntegration:
    def test_override_crud(self, mock_client):
        """Create, get, modify, delete override."""
        service = OverridesService(mock_client)

        created = service.create(text="Test override", nvt_oid="1.3.6.1.4.1.25623.1.0.12345")
        override_id = created.get("id")
        assert override_id

        overrides = service.list()
        assert any(o.get("id") == override_id for o in overrides)

        service.modify(override_id, text="Updated override")
        service.delete(override_id)
```

### 4.6 Scan Configs Service (read-only)

```python
@pytest.mark.integration
class TestScanConfigsServiceIntegration:
    def test_list_scan_configs(self, mock_client):
        """List scan configs (empty is OK — validates response parsing)."""
        service = ScanConfigsService(mock_client)
        configs = service.list()
        assert configs is not None
```

### 4.7 Schedules Service (read-only)

```python
@pytest.mark.integration
class TestSchedulesServiceIntegration:
    def test_list_schedules(self, mock_client):
        service = SchedulesService(mock_client)
        schedules = service.list()
        assert schedules is not None
```

### 4.8 Port Lists Service (read-only)

```python
@pytest.mark.integration
class TestPortListsServiceIntegration:
    def test_list_port_lists(self, mock_client):
        service = PortListsService(mock_client)
        port_lists = service.list()
        assert port_lists is not None
```

### 4.9 Reports Service

```python
@pytest.mark.integration
class TestReportsServiceIntegration:
    def test_list_reports(self, mock_client):
        """Reports generated by task starts should be listable."""
        service = ReportsService(mock_client)
        reports = service.list()
        assert reports is not None
```

### 4.10 Tickets Service

```python
@pytest.mark.integration
class TestTicketsServiceIntegration:
    def test_ticket_crud(self, mock_client):
        """Create, modify status, delete ticket."""
        service = TicketsService(mock_client)

        created = service.create(
            result_id="11111111-1111-1111-1111-111111111111",
            comment="Test ticket",
        )
        ticket_id = created.get("id")
        assert ticket_id

        service.modify(ticket_id, status="closed", comment="Resolved")
        service.delete(ticket_id)
```

---

## 5. CI Workflow Addition

Add an `integration` job to `.github/workflows/ci.yml`:

```yaml
  integration:
    name: Integration Tests (mock server)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install Poetry
        uses: snok/install-poetry@v1
        with:
          virtualenvs-create: true
          virtualenvs-in-project: true

      - name: Install dependencies
        run: poetry install --no-interaction

      - name: Download gvm-mock-server
        run: |
          curl -sL https://github.com/clawosiris/rust-gvm/releases/download/nightly/gvm-mock-server-linux-amd64-musl.tar.gz \
            | tar xz
          chmod +x gvm-mock-server
          echo "GVM_MOCK_SERVER_BIN=$(pwd)/gvm-mock-server" >> "$GITHUB_ENV"

      - name: Run integration tests
        run: poetry run pytest tests/integration -m integration -v
```

---

## 6. Directory Structure

```
tests/
├── conftest.py                    # existing
├── unit/                          # existing unit tests (unchanged)
├── e2e/                           # existing (live server)
└── integration/                   # NEW: mock server tests
    ├── __init__.py
    ├── conftest.py                # mock_server, mock_client fixtures
    ├── test_targets.py
    ├── test_tasks.py
    ├── test_notes.py
    ├── test_overrides.py
    ├── test_tickets.py
    ├── test_reports.py
    ├── test_scan_configs.py
    ├── test_schedules.py
    └── test_port_lists.py
```

---

## 7. Implementation Notes

### Session-scoped fixtures
The mock server starts once per test session (not per test). This is fast and matches how a real gvmd would be used. Tests share state — a target created in one test is visible in another. This is intentional: it tests the cumulative behavior of the service layer.

### Test ordering
Tests within a class can depend on prior state (e.g., task lifecycle test creates → starts → stops). Use `pytest-ordering` or structure as sequential steps within a single test method.

### Skipping when binary is missing
```python
@pytest.fixture(scope="session")
def mock_server():
    import shutil
    if not shutil.which(MOCK_SERVER_BIN):
        pytest.skip("gvm-mock-server not found; install or set GVM_MOCK_SERVER_BIN")
    # ...
```

### Pinning mock server version
For reproducible CI, consider pinning to a tagged release instead of nightly once rust-gvm publishes its first release (e.g., `v0.1.0`). Until then, nightly is fine — the rust-gvm CI validates the mock server against python-gvm on every push.

---

## 8. Success Criteria

- [ ] All service methods that touch GMP are exercised through the mock server
- [ ] python-gvm's XML parser validates all mock server responses (no parse errors)
- [ ] Version negotiation (two-connection flow) works transparently
- [ ] CI job passes on every PR
- [ ] Integration tests can be skipped locally when binary is not available
- [ ] No changes to existing unit tests required
