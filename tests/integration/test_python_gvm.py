#!/usr/bin/env python3

from __future__ import annotations

import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable

from gvm.connections import UnixSocketConnection
from gvm.errors import GvmError
from gvm.protocols.gmp import GMP
from gvm.transforms import EtreeCheckCommandTransform


REPO_ROOT = Path(__file__).resolve().parents[2]
BINARY = REPO_ROOT / "target" / "debug" / "gvm-mock-server"
CONFIG_ID = "daba56c8-73ec-11df-a475-002264764cea"
SCANNER_ID = "08b69003-5fc2-4037-a479-93b440211c73"


def build_binary() -> None:
    subprocess.run(
        ["cargo", "build", "-p", "gvm-mock-server"],
        cwd=REPO_ROOT,
        check=True,
    )


def wait_for_socket(socket_path: Path, process: subprocess.Popen[str]) -> None:
    deadline = time.time() + 10
    while time.time() < deadline:
        if socket_path.exists():
            return
        if process.poll() is not None:
            raise RuntimeError("mock server exited before creating the socket")
        time.sleep(0.05)
    raise TimeoutError(f"socket was not created at {socket_path}")


def response_id(response) -> str:
    resource_id = response.get("id")
    if not resource_id:
        raise RuntimeError("response did not contain an id attribute")
    return resource_id


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def require_gvm_error(fn: Callable[[], None], message: str) -> None:
    try:
        fn()
    except GvmError:
        return
    raise AssertionError(message)


def run_step(name: str, fn: Callable[[], None]) -> bool:
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL {name}: {exc}")
        return False
    print(f"PASS {name}")
    return True


def main() -> int:
    build_binary()

    with tempfile.TemporaryDirectory(prefix="gvm-mock-server-") as temp_dir:
        socket_path = Path(temp_dir) / "mock-gmp.sock"
        server = subprocess.Popen(
            [
                str(BINARY),
                "--mode",
                "stateful",
                "--version",
                "22.5",
                "--socket",
                str(socket_path),
            ],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        try:
            wait_for_socket(socket_path, server)

            conn = UnixSocketConnection(path=str(socket_path))
            transform = EtreeCheckCommandTransform()

            state: dict[str, str] = {}

            with GMP(connection=conn, transform=transform) as gmp:
                def require_host(comment: str) -> None:
                    response = gmp.get_host(
                        host_id=state["host_id"], details=True
                    )
                    asset = response.find("asset")
                    require(asset is not None, "created host asset was not returned")
                    require(
                        asset.get("id") == state["host_id"],
                        "returned host asset had the wrong id",
                    )
                    require(
                        asset.findtext("type") == "host",
                        "host asset did not use the canonical type element",
                    )
                    require(
                        asset.find("host") is not None,
                        "host asset did not include the canonical host payload",
                    )
                    require(
                        asset.findtext("comment") == comment,
                        "host asset comment did not match",
                    )

                checks = [
                    (
                        "authenticate",
                        lambda: gmp.authenticate(username="admin", password="admin"),
                    ),
                    (
                        "create_target",
                        lambda: state.setdefault(
                            "target_id",
                            response_id(
                                gmp.create_target(
                                    name="Python Target",
                                    hosts=["192.168.1.10"],
                                )
                            ),
                        ),
                    ),
                    (
                        "get_targets",
                        lambda: require(
                            any(
                                target.get("id") == state["target_id"]
                                for target in gmp.get_targets().findall("target")
                            ),
                            "created target not returned by get_targets",
                        ),
                    ),
                    (
                        "create_host",
                        lambda: state.setdefault(
                            "host_id",
                            response_id(
                                gmp.create_host(
                                    name="192.0.2.20",
                                    comment="created through python-gvm",
                                )
                            ),
                        ),
                    ),
                    (
                        "get_host_canonical",
                        lambda: require_host("created through python-gvm"),
                    ),
                    (
                        "modify_host",
                        lambda: gmp.modify_host(
                            host_id=state["host_id"],
                            comment="updated through python-gvm",
                        ),
                    ),
                    (
                        "get_host_modified",
                        lambda: require_host("updated through python-gvm"),
                    ),
                    (
                        "create_task",
                        lambda: state.setdefault(
                            "task_id",
                            response_id(
                                gmp.create_task(
                                    name="Python Task",
                                    config_id=CONFIG_ID,
                                    target_id=state["target_id"],
                                    scanner_id=SCANNER_ID,
                                )
                            ),
                        ),
                    ),
                    (
                        "start_task",
                        lambda: state.setdefault(
                            "report_id", gmp.start_task(task_id=state["task_id"]).findtext("report_id") or ""
                        ),
                    ),
                    (
                        "get_task_status_running",
                        lambda: require(
                            any(
                                task.get("id") == state["task_id"]
                                and task.findtext("status") == "Running"
                                for task in gmp.get_tasks().findall("task")
                            ),
                            "task status was not Running after start_task",
                        ),
                    ),
                    (
                        "stop_task",
                        lambda: gmp.stop_task(task_id=state["task_id"]),
                    ),
                    (
                        "get_tasks",
                        lambda: require(
                            any(
                                task.get("id") == state["task_id"]
                                and task.findtext("status") == "Stopped"
                                for task in gmp.get_tasks().findall("task")
                            ),
                            "task status was not Stopped after stop_task",
                        ),
                    ),
                    (
                        "resume_task",
                        lambda: state.setdefault(
                            "resumed_report_id",
                            gmp.resume_task(task_id=state["task_id"]).findtext("report_id") or "",
                        ),
                    ),
                    (
                        "resume_reuses_report",
                        lambda: require(
                            state["resumed_report_id"] == state["report_id"],
                            "resume_task did not reuse the stopped report",
                        ),
                    ),
                    (
                        "stop_resumed_task",
                        lambda: gmp.stop_task(task_id=state["task_id"]),
                    ),
                    (
                        "referenced_target_delete_rejected",
                        lambda: require_gvm_error(
                            lambda: gmp.delete_target(target_id=state["target_id"]),
                            "delete_target should reject a target referenced by a live task",
                        ),
                    ),
                    (
                        "create_note",
                        lambda: state.setdefault(
                            "note_id",
                            response_id(
                                gmp.create_note(
                                    text="Python note",
                                    nvt_oid="1.3.6.1.4.1.25623.1.0.12345",
                                    hosts=["192.168.1.10"],
                                )
                            ),
                        ),
                    ),
                    (
                        "get_notes",
                        lambda: require(
                            any(
                                note.get("id") == state["note_id"]
                                for note in gmp.get_notes().findall("note")
                            ),
                            "created note not returned by get_notes",
                        ),
                    ),
                    (
                        "modify_note",
                        lambda: gmp.modify_note(
                            note_id=state["note_id"],
                            text="Python note updated",
                            hosts=["192.168.1.11"],
                        ),
                    ),
                    (
                        "delete_note",
                        lambda: gmp.delete_note(note_id=state["note_id"]),
                    ),
                    (
                        "delete_host",
                        lambda: gmp.delete_host(host_id=state["host_id"]),
                    ),
                    (
                        "get_hosts_after_delete",
                        lambda: require(
                            all(
                                host.get("id") != state["host_id"]
                                for host in gmp.get_hosts().findall("asset")
                            ),
                            "deleted host was still returned by get_hosts",
                        ),
                    ),
                    (
                        "delete_task",
                        lambda: gmp.delete_task(task_id=state["task_id"]),
                    ),
                    (
                        "delete_target",
                        lambda: gmp.delete_target(target_id=state["target_id"]),
                    ),
                ]

                all_ok = run_step(
                    "version_negotiation",
                    lambda: require(gmp.get_version().findtext("version") == "22.5", "expected GMP 22.5"),
                )

                for name, fn in checks:
                    all_ok = run_step(name, fn) and all_ok

            return 0 if all_ok else 1
        finally:
            if server.poll() is None:
                server.send_signal(signal.SIGINT)
            try:
                stdout, stderr = server.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                stdout, stderr = server.communicate(timeout=5)
            if server.returncode not in (0, -signal.SIGINT):
                sys.stderr.write(stdout)
                sys.stderr.write(stderr)


if __name__ == "__main__":
    raise SystemExit(main())
