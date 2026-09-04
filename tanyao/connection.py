"""Synchronous agent connection: hello/auth handshake, strict request-response, keepalive.

Implements PROTOCOL.md sections 1, 2, 3, 5, 6.
"""

from __future__ import annotations

import hashlib
import os
import socket
import time

from .constants import (
    DEFAULT_PORT,
    FLAG_ERROR,
    ProtocolError,
)
from .frames import Frame, FrameDecoder, encode_frame


class AgentError(Exception):
    """Application-level error reported by the agent (ERROR frame) or transport."""

    def __init__(self, error: str, errno: int | None = None, detail: str = "") -> None:
        super().__init__(f"{error}" + (f" (errno={errno})" if errno is not None else "") + (f": {detail}" if detail else ""))
        self.error = error
        self.errno = errno
        self.detail = detail


def _parse_caps(value) -> int:
    """hello.capabilities → int bitmap. Absent (v1.0 agent) means 0."""
    if value is None:
        return 0
    if isinstance(value, bool):
        raise ProtocolError("hello capabilities must be an int/hex bitmap")
    if isinstance(value, int):
        if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
            raise ProtocolError(f"hello capabilities out of u64 range: {value}")
        return value
    if isinstance(value, str):
        text = value.strip().lower()
        if not text.startswith("0x"):
            raise ProtocolError(f"hello capabilities must be 0x hex, got {value!r}")
        try:
            return int(text, 16)
        except ValueError as exc:
            raise ProtocolError(f"bad hello capabilities {value!r}") from exc
    raise ProtocolError(f"bad hello capabilities type {type(value).__name__}")


class AgentConnection:
    """One TCP connection to tanyao-agent. Not thread-safe; guard with a lock if shared."""

    def __init__(
        self,
        host: str,
        port: int = DEFAULT_PORT,
        token: str | None = None,
        *,
        connect_timeout: float = 5.0,
        request_timeout: float = 30.0,
    ) -> None:
        self._host = host
        self._port = port
        self._token = token if token is not None else os.environ.get("TANYAO_TOKEN", "")
        self._connect_timeout = connect_timeout
        self._request_timeout = request_timeout
        self._sock: socket.socket | None = None
        self._decoder = FrameDecoder()
        self._seq = 0
        self.generation: int | None = None
        self.agent_version: str | None = None
        # Agent-layer capability bitmap (hello.capabilities, PROTOCOL.md §7.1).
        # 0 for v1.0 agents that do not send the field. Engine dispatch reads
        # ONLY this bitmap — never the hello version string.
        self.agent_capabilities: int = 0
        self.authenticated = False
        self.connected_at: float | None = None

    # -- transport -----------------------------------------------------------

    @property
    def is_connected(self) -> bool:
        return self._sock is not None

    def connect(self) -> None:
        if self._sock is not None:
            return
        sock = socket.create_connection((self._host, self._port), timeout=self._connect_timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._sock = sock
        self._decoder = FrameDecoder()
        self.connected_at = time.monotonic()

        hello = self._recv_frame(timeout=self._connect_timeout)
        if hello.cmd != 0 or hello.is_response or hello.is_error:
            raise ProtocolError(f"expected hello frame, got cmd={hello.cmd} flags={hello.flags}")
        challenge = hello.payload.get("challenge")
        if not isinstance(challenge, str) or len(challenge) != 64:
            raise ProtocolError("hello payload missing 64-hex challenge")
        self.generation = int(hello.payload.get("generation", 0))
        self.agent_version = hello.payload.get("version")
        self.agent_capabilities = _parse_caps(hello.payload.get("capabilities"))

        proof = hashlib.sha256((self._token + challenge).encode("utf-8")).hexdigest()
        resp = self.request(1, {"proof": proof}, authenticate=False)
        if resp.get("ok") is not True:
            raise AgentError("auth_failed", detail="agent rejected auth response")
        self.authenticated = True

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None
        self.authenticated = False

    def shutdown_peer(self) -> None:
        """Ask the agent to exit, then close."""
        if self._sock is not None:
            try:
                self.request(3, {})
            except (AgentError, ProtocolError, OSError):
                pass
            self.close()

    # -- request/response ----------------------------------------------------

    def request_raw(self, cmd: int, payload: dict, *, authenticate: bool = True) -> Frame:
        """Like request(), but returns the raw response Frame — used by ops
        whose success response is a PAYLOAD_BINARY frame (draft §2: dump_pull,
        symbol_batch packed). ERROR frames are still raised as AgentError."""
        if self._sock is None:
            raise AgentError("not_connected", detail="call connect() first")
        if authenticate and not self.authenticated:
            raise AgentError("auth_required", detail="connection is not authenticated")
        self._seq = (self._seq + 1) & 0xFFFFFFFF
        frame = Frame(flags=0, seq=self._seq, cmd=cmd, payload=payload)
        wire = encode_frame(frame)
        self._sock.settimeout(self._request_timeout)
        self._sock.sendall(wire)
        while True:
            resp = self._recv_frame(timeout=self._request_timeout)
            if resp.seq != frame.seq or resp.cmd != frame.cmd:
                raise ProtocolError(
                    f"response seq/cmd mismatch: got seq={resp.seq} cmd={resp.cmd}, want seq={frame.seq} cmd={frame.cmd}"
                )
            if not resp.is_response:
                # Per spec, agent never pushes frames other than hello. Treat as fatal.
                raise ProtocolError(f"unexpected non-response frame cmd={resp.cmd}")
            if resp.flags & FLAG_ERROR:
                if not isinstance(resp.payload, dict):
                    raise ProtocolError("ERROR frame with binary payload")
                err = resp.payload.get("error", "unknown")
                errno = resp.payload.get("errno")
                detail = resp.payload.get("detail", "")
                raise AgentError(str(err), errno=int(errno) if isinstance(errno, int) else None, detail=str(detail))
            return resp

    def request(self, cmd: int, payload: dict, *, authenticate: bool = True) -> dict:
        """Send one request and wait for the matching JSON response. Raises
        AgentError on ERROR frames, ProtocolError on framing violations."""
        resp = self.request_raw(cmd, payload, authenticate=authenticate)
        if isinstance(resp.payload, bytes):
            raise ProtocolError(f"cmd {cmd}: unexpected binary payload for JSON op")
        return resp.payload

    def ping(self) -> dict:
        return self.request(2, {})

    def has_cap(self, bit: int) -> bool:
        """True when the agent declared the given capability. `bit` is a mask
        (AGENT_CAP_* constants), not a bit index."""
        return bool(self.agent_capabilities & bit)

    # -- internal -------------------------------------------------------------

    def _recv_frame(self, timeout: float) -> Frame:
        assert self._sock is not None
        self._sock.settimeout(timeout)
        deadline = time.monotonic() + timeout
        while True:
            frame = self._decoder.pop()
            if frame is not None:
                return frame
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"no frame within {timeout}s")
            try:
                chunk = self._sock.recv(65536)
            except socket.timeout as exc:
                raise TimeoutError(f"no frame within {timeout}s") from exc
            if not chunk:
                raise ConnectionError("agent closed the connection")
            self._decoder.feed(chunk)
