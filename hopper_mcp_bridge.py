#!/usr/bin/env python3
"""Codex-facing MCP bridge for HopperPyMCP.

Hopper v4 embeds Python 3.9, but current FastMCP requires Python 3.10+.
This bridge runs outside Hopper in a modern venv. Each MCP call writes a request
file, triggers Hopper's script menu, and waits for the one-shot response file.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field


DEFAULT_REQUEST_DIR = "/tmp/hopper_mcp_requests"
DEFAULT_HOPPER_PROCESS = "Hopper Disassembler v4"
DEFAULT_HOPPER_MENU_ITEM = "Hopper MCP Start Server"
REQUEST_DIR = Path(os.environ.get("HOPPER_MCP_REQUEST_DIR", DEFAULT_REQUEST_DIR))
HOPPER_PROCESS = os.environ.get("HOPPER_MCP_PROCESS", DEFAULT_HOPPER_PROCESS)
HOPPER_MENU_ITEM = os.environ.get("HOPPER_MCP_MENU_ITEM", DEFAULT_HOPPER_MENU_ITEM)
REQUEST_TIMEOUT_SEC = float(os.environ.get("HOPPER_MCP_TIMEOUT_SEC", "105"))
REQUEST_SUFFIX = ".request.json"
RESPONSE_SUFFIX = ".response.json"
RUNNING_SUFFIX = ".running.json"

mcp = FastMCP(name="Hopper MCP")


def _json_dump_atomic(path: Path, payload: dict) -> None:
    tmp_path = path.with_name(f"{path.name}.tmp.{os.getpid()}")
    tmp_path.write_text(json.dumps(payload), encoding="utf-8")
    tmp_path.replace(path)


def _cleanup_old_requests(max_age_sec: int = 3600) -> None:
    now = time.time()
    REQUEST_DIR.mkdir(parents=True, exist_ok=True)
    for path in REQUEST_DIR.iterdir():
        if not path.name.endswith((REQUEST_SUFFIX, RESPONSE_SUFFIX, RUNNING_SUFFIX)):
            continue
        try:
            if now - path.stat().st_mtime > max_age_sec:
                path.unlink()
        except OSError:
            pass


def _osascript_quote(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _trigger_hopper_script() -> None:
    process_name = _osascript_quote(HOPPER_PROCESS)
    menu_item_name = _osascript_quote(HOPPER_MENU_ITEM)
    script = f'''
tell application "System Events"
  if not (exists process "{process_name}") then
    error "Hopper process is not running: {process_name}"
  end if
  tell process "{process_name}"
    set frontmost to true
    click menu bar item "Scripts" of menu bar 1
    delay 0.15
    click menu item "{menu_item_name}" of menu "Scripts" of menu bar item "Scripts" of menu bar 1
  end tell
end tell
'''
    result = subprocess.run(
        ["osascript"],
        input=script,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    if result.returncode != 0:
        error = result.stderr.strip() or result.stdout.strip() or "unknown AppleScript error"
        raise RuntimeError(
            "Could not trigger Hopper MCP script. Make sure Hopper is open with an "
            f"analyzed document and Scripts > {HOPPER_MENU_ITEM} is available. "
            f"AppleScript error: {error}"
        )


def _wait_for_response(response_path: Path, request_path: Path, running_path: Path) -> dict:
    deadline = time.monotonic() + REQUEST_TIMEOUT_SEC
    while time.monotonic() < deadline:
        if response_path.exists():
            try:
                payload = json.loads(response_path.read_text(encoding="utf-8"))
            finally:
                try:
                    response_path.unlink()
                except OSError:
                    pass
            return payload
        time.sleep(0.2)

    pending_state = "pending"
    if running_path.exists():
        pending_state = "running in Hopper"
    elif not request_path.exists():
        pending_state = "claimed by Hopper but no response was written"
    raise RuntimeError(
        f"Hopper MCP request timed out after {REQUEST_TIMEOUT_SEC:.0f}s "
        f"({pending_state}). Request id: {request_path.name[:-len(REQUEST_SUFFIX)]}"
    )


def _call_hopper(tool: str, **args):
    _cleanup_old_requests()
    request_id = uuid.uuid4().hex
    request_path = REQUEST_DIR / f"{request_id}{REQUEST_SUFFIX}"
    running_path = REQUEST_DIR / f"{request_id}{RUNNING_SUFFIX}"
    response_path = REQUEST_DIR / f"{request_id}{RESPONSE_SUFFIX}"

    _json_dump_atomic(request_path, {"id": request_id, "tool": tool, "args": args})
    try:
        _trigger_hopper_script()
        payload = _wait_for_response(response_path, request_path, running_path)
    except Exception:
        for path in (request_path, running_path, response_path):
            try:
                path.unlink()
            except OSError:
                pass
        raise
    if not payload.get("ok"):
        error = payload.get("error", "unknown Hopper MCP request error")
        raise RuntimeError(error)
    return payload.get("result")


@mcp.tool
def get_all_documents() -> dict:
    """Get information about all currently opened Hopper documents."""
    return _call_hopper("get_all_documents")


@mcp.tool
def get_current_document() -> dict:
    """Get information about the current Hopper document."""
    return _call_hopper("get_current_document")


@mcp.tool
def set_current_document(
    doc_id: Annotated[int, Field(description="Document ID from get_all_documents()", ge=0)]
) -> str:
    """Set the current Hopper document by doc_id."""
    return _call_hopper("set_current_document", doc_id=doc_id)


@mcp.tool
def rebase_document(
    new_base_address_hex: Annotated[str, "New base address as a hex string, e.g. 0x100000000"]
) -> str:
    """Rebase the current Hopper document to a new base address."""
    return _call_hopper("rebase_document", new_base_address_hex=new_base_address_hex)


@mcp.tool
def list_all_segments() -> dict:
    """List all segments in the current Hopper document."""
    return _call_hopper("list_all_segments")


@mcp.tool
def search_names_regex(
    regex_pattern: Annotated[str, "Regular expression pattern to search for in names"],
    segment_name: Annotated[str, "Target segment name, e.g. __TEXT or TEXT"],
    search_type: Annotated[str, "Name type: bare, demangled, or both"] = "both",
    max_results: Annotated[int, Field(description="Maximum number of results", ge=1)] = 20,
) -> dict:
    """Search named addresses in a segment using a regular expression."""
    return _call_hopper(
        "search_names_regex",
        regex_pattern=regex_pattern,
        segment_name=segment_name,
        search_type=search_type,
        max_results=max_results,
    )


@mcp.tool
def search_strings_regex(
    regex_pattern: Annotated[str, "Regular expression pattern to search for in strings"],
    segment_name: Annotated[str, "Target segment name, e.g. __TEXT or TEXT"],
    max_results: Annotated[int, Field(description="Maximum number of results", ge=1)] = 20,
) -> dict:
    """Search strings in a segment using a regular expression."""
    return _call_hopper(
        "search_strings_regex",
        regex_pattern=regex_pattern,
        segment_name=segment_name,
        max_results=max_results,
    )


@mcp.tool
def get_string_at_addr(
    address_hex: Annotated[str, "Memory address as a hex string, e.g. 0x1000"]
) -> str:
    """Get the string content at a specific address."""
    return _call_hopper("get_string_at_addr", address_hex=address_hex)


@mcp.tool
def get_address_info(
    address_or_name_list: Annotated[
        list[str],
        "Addresses as hex strings or names; maximum 50 entries",
    ]
) -> dict:
    """Get segment, type, procedure, instruction, and reference info for addresses or names."""
    return _call_hopper("get_address_info", address_or_name_list=address_or_name_list)


@mcp.tool
def get_call_graph(
    start_addr_hex: Annotated[str, "Starting address as a hex string"],
    direction: Annotated[str, "forward, backward, or bidirectional"] = "forward",
    max_depth: Annotated[int, Field(description="Maximum traversal depth", ge=1, le=10)] = 2,
) -> dict:
    """Return a call graph starting from a specific procedure address."""
    return _call_hopper(
        "get_call_graph",
        start_addr_hex=start_addr_hex,
        direction=direction,
        max_depth=max_depth,
    )


@mcp.tool
def decompile_procedure(
    address_or_name: Annotated[str, "Procedure address as hex string or procedure name"]
) -> str:
    """Decompile a procedure to C-like pseudocode."""
    return _call_hopper("decompile_procedure", address_or_name=address_or_name)


@mcp.tool
def disassemble_procedure(
    address_or_name: Annotated[str, "Procedure address as hex string or procedure name"]
) -> str:
    """Disassemble a procedure into assembly instructions."""
    return _call_hopper("disassemble_procedure", address_or_name=address_or_name)


@mcp.tool
def get_demangled_name(
    address_or_name: Annotated[str, "Address as hex string or symbol name"]
) -> dict:
    """Get the demangled name at an address or for a symbol."""
    return _call_hopper("get_demangled_name", address_or_name=address_or_name)


@mcp.tool
def get_comment_at_address(
    address_hex: Annotated[str, "Memory address as a hex string"]
) -> str:
    """Get the comment at a specific address."""
    return _call_hopper("get_comment_at_address", address_hex=address_hex)


@mcp.tool
def set_comment_at_address(
    address_hex: Annotated[str, "Memory address as a hex string"],
    comment: Annotated[str, "Comment text to set"],
) -> str:
    """Set a comment at a specific address and save the Hopper document."""
    return _call_hopper("set_comment_at_address", address_hex=address_hex, comment=comment)


@mcp.tool
def set_name_at_address(
    address_hex: Annotated[str, "Memory address as a hex string"],
    name: Annotated[str, "Name or label to set"],
) -> str:
    """Set a name or label at a specific address and save the Hopper document."""
    return _call_hopper("set_name_at_address", address_hex=address_hex, name=name)


@mcp.tool
def mark_data_type_at_address(
    address_hex: Annotated[str, "Memory address as a hex string"],
    data_type: Annotated[
        str,
        "code, procedure, int8, int16, int32, int64, ascii, unicode, undefined, "
        "byte_array, short_array, or int_array",
    ],
    length: Annotated[int, Field(description="Length for data types", ge=1)] = 1,
) -> str:
    """Mark data type at an address and save the Hopper document."""
    return _call_hopper(
        "mark_data_type_at_address",
        address_hex=address_hex,
        data_type=data_type,
        length=length,
    )


def main() -> None:
    global REQUEST_DIR, HOPPER_PROCESS, HOPPER_MENU_ITEM, REQUEST_TIMEOUT_SEC

    parser = argparse.ArgumentParser(description="Codex-facing MCP bridge for HopperPyMCP")
    parser.add_argument("--request-dir", default=str(REQUEST_DIR), help="Directory for one-shot Hopper request files")
    parser.add_argument("--hopper-process", default=HOPPER_PROCESS, help="macOS Accessibility process name for Hopper")
    parser.add_argument("--menu-item", default=HOPPER_MENU_ITEM, help="Hopper Scripts menu item to trigger")
    parser.add_argument("--timeout-sec", type=float, default=REQUEST_TIMEOUT_SEC, help="Per-request timeout")
    parser.add_argument("--hopper-rpc", default=None, help=argparse.SUPPRESS)
    args = parser.parse_args()
    REQUEST_DIR = Path(args.request_dir)
    HOPPER_PROCESS = args.hopper_process
    HOPPER_MENU_ITEM = args.menu_item
    REQUEST_TIMEOUT_SEC = args.timeout_sec
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
