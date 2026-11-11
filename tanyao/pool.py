"""Connection pool over tanyao-agent, with per-target affinity.

Protocol background
-------------------
PROTOCOL.md §1 historically allowed exactly ONE authenticated connection, so
the host serialized every RPC behind a single socket plus a global lock.
Measured cost: 20 concurrent reads ran at 1.5x a serial loop (effectively no
parallelism), and multi-target work paid an open/close round trip per switch.

Agent capability bit 14 (MULTI_CONN, v1.5) relaxes the connection limit: the
agent accepts up to N authenticated connections when started with
`--max-connections N`.

Affinity is mandatory, not an optimisation
------------------------------------------
A kernel target handle is registered in the AGENT's per-connection target
list, so a handle opened on connection A is invisible on connection B
(verified: cross-connection use answers status -2 / ENOENT). Each target must
therefore stay pinned to the connection that opened it; the pool only
parallelises work belonging to *different* targets.

When the agent does not declare MULTI_CONN the pool stays at size 1 and behaves
exactly like the old single-connection path.
"""

from __future__ import annotations

import threading
import time
from contextlib import contextmanager

from .connection import AgentConnection, AgentError

# One connection per concurrently open target is the useful ceiling for current
# workloads (analysing a handful of processes at a time).
DEFAULT_POOL_SIZE = 1


def _taints_connection(exc: AgentError) -> bool:
    """True when this business error also invalidated the byte stream."""
    return exc.error in ("protocol_error", "auth_failed", "auth_required")


def _unavailable(msg: str) -> Exception:
    """Build the service-layer AgentUnavailable without a module-level import
    (service imports this module, so a top-level import would be circular)."""
    from .service import AgentUnavailable
    return AgentUnavailable(msg)


class ConnectionPool:
    """Bounded pool of authenticated AgentConnections + target affinity map."""

    def __init__(
        self,
        host: str,
        port: int,
        token: str | None,
        *,
        size: int = DEFAULT_POOL_SIZE,
        wait_timeout: float | None = 30.0,
        connect_timeout: float = 15.0,
    ) -> None:
        self._host = host
        self._port = port
        self._token = token
        self._size = max(1, int(size))
        self._wait_timeout = wait_timeout
        self._connect_timeout = connect_timeout
        self._cond = threading.Condition()
        self._idle: list[AgentConnection] = []
        self._busy: set[AgentConnection] = set()
        self._total = 0
        self._closed = False
        self._affinity: dict[int, AgentConnection] = {}  # pid -> owning conn
        # Connections that own at least one target. They are excluded from
        # generic checkout() so each concurrently opened target gets its own
        # socket instead of sharing one and serialising again.
        self._pinned: set[AgentConnection] = set()
        # One mutex per connection: AgentConnection is not thread-safe, and
        # two threads interleaving frames on one socket corrupts seq numbers.
        self._conn_locks: dict[AgentConnection, threading.RLock] = {}

    # -- introspection ---------------------------------------------------------

    @property
    def size(self) -> int:
        with self._cond:
            return self._size

    def set_size(self, size: int) -> None:
        with self._cond:
            self._size = max(1, int(size))

    def stats(self) -> dict:
        with self._cond:
            return {"size": self._size, "open": self._total,
                    "idle": len(self._idle), "busy": len(self._busy),
                    "affinity": len(self._affinity)}

    # -- affinity --------------------------------------------------------------

    def affinity_for(self, pid: int) -> AgentConnection | None:
        with self._cond:
            return self._affinity.get(pid)

    def bind_affinity(self, pid: int, conn: AgentConnection) -> None:
        with self._cond:
            self._affinity[pid] = conn
            self._pinned.add(conn)

    def drop_affinity(self, pid: int) -> None:
        with self._cond:
            conn = self._affinity.pop(pid, None)
            if conn is not None and conn not in self._affinity.values():
                self._pinned.discard(conn)

    def _drop_affinity_for(self, conn: AgentConnection) -> None:
        with self._cond:
            for pid in [p for p, c in self._affinity.items() if c is conn]:
                self._affinity.pop(pid, None)

    def is_closed(self) -> bool:
        with self._cond:
            return self._closed

    def adopt(self, conn: AgentConnection) -> None:
        """Register an already-authenticated connection as pool member #0.

        The service opens one control connection during connect(); adopting it
        avoids a redundant socket (a single-slot agent would answer busy)."""
        with self._cond:
            if self._closed:
                return
            if conn not in self._idle:
                self._idle.append(conn)
            self._total += 1

    # -- checkout --------------------------------------------------------------

    @contextmanager
    def checkout(self, *, prefer: AgentConnection | None = None):
        """Yield an exclusive connection, returning it to the pool afterwards.

        prefer: pin to a specific connection (target affinity). If it is busy,
        wait for it instead of switching, since switching invalidates handles.
        """
        conn = self._acquire(prefer)
        healthy = True
        try:
            yield conn
        except (ConnectionError, TimeoutError, OSError):
            # Transport-level failure: the socket is untrustworthy, discard it.
            healthy = False
            raise
        except AgentError as exc:
            # Business error (not_found / bad_request / gate-off ...). The
            # connection is perfectly healthy — discarding it here would also
            # drop the target affinity for every pid pinned to it, which is
            # exactly the "target lost after any failed op" bug. Only protocol
            # desyncs taint the stream.
            if _taints_connection(exc):
                healthy = False
            raise
        finally:
            self._release(conn, healthy)

    def _acquire(self, prefer: AgentConnection | None) -> AgentConnection:
        grew = False
        with self._cond:
            if self._closed:
                raise _unavailable("connection pool is closed")

            if prefer is not None:
                if prefer in self._idle:
                    self._idle.remove(prefer)
                elif not self._wait_busy(prefer):
                    raise _unavailable("affinity connection busy (timeout)")
                if not prefer.is_connected:
                    # Reap instead of handing back a corpse.
                    self._total -= 1
                    self._affinity = {p: cc for p, cc in self._affinity.items()
                                      if cc is not prefer}
                    try:
                        prefer.close()
                    except OSError:
                        pass
                    self._cond.notify_all()
                    raise _unavailable("affinity connection was closed by peer")
                self._busy.add(prefer)
                return prefer

            # Reap dead idle connections before handing one out. A peer that
            # closed its side leaves us with a socket stuck in CLOSE-WAIT: the
            # fd is still valid, so `is_connected` stays true, but every request
            # on it fails and — worse — the agent keeps that connection SLOT
            # occupied, so after enough churn the listener answers `busy` to
            # every new connection and the whole tool surface dies with
            # "expected hello frame, got cmd=0 flags=3".
            free = [c for c in self._idle
                    if c not in self._pinned and c.is_connected]
            if len(free) != len([c for c in self._idle if c not in self._pinned]):
                dead = [c for c in self._idle
                        if c not in self._pinned and not c.is_connected]
                for c in dead:
                    self._idle.remove(c)
                    self._total -= 1
                    self._affinity = {p: cc for p, cc in self._affinity.items()
                                      if cc is not c}
                    try:
                        c.close()
                    except OSError:
                        pass
            if free:
                conn = free[0]
                self._idle.remove(conn)
                self._busy.add(conn)
                return conn
            if self._total < self._size:
                self._total += 1
                grew = True
            else:
                if not self._wait_idle():
                    raise _unavailable("no free agent connection (pool exhausted)")
                conn = self._idle.pop()
                self._busy.add(conn)
                return conn

        assert grew
        try:
            conn = self._new_connection()
        except BaseException:
            with self._cond:
                self._total -= 1
                self._cond.notify_all()
            raise
        with self._cond:
            self._busy.add(conn)
        return conn

    def lock_for(self, conn: AgentConnection) -> threading.RLock:
        """Return the mutex guarding `conn` (creates it on first use)."""
        with self._cond:
            lock = self._conn_locks.get(conn)
            if lock is None:
                lock = threading.RLock()
                self._conn_locks[conn] = lock
            return lock

    def _release(self, conn: AgentConnection, healthy: bool) -> None:
        with self._cond:
            self._busy.discard(conn)
            if healthy and conn.is_connected and not self._closed:
                # Idempotent: a connection can only ever appear ONCE in the idle
                # list. Re-entrant/nested checkouts (e.g. an affinity checkout
                # inside another) would otherwise append duplicates and make
                # len(idle) diverge from _total.
                if conn not in self._idle:
                    self._idle.append(conn)
            else:
                self._total -= 1
                self._pinned.discard(conn)
                for pid in [p for p, c in self._affinity.items() if c is conn]:
                    self._affinity.pop(pid, None)
                try:
                    conn.close()
                except OSError:
                    pass
            self._cond.notify_all()

    def _wait_busy(self, conn: AgentConnection) -> bool:
        """Wait until conn is not busy. Caller holds self._cond."""
        if conn not in self._busy:
            return True
        deadline = None if self._wait_timeout is None else time.monotonic() + self._wait_timeout
        while conn in self._busy:
            if deadline is None:
                self._cond.wait()
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            self._cond.wait(remaining)
        return True

    def _wait_idle(self) -> bool:
        """Wait until a non-pinned connection is idle. Caller holds self._cond."""
        deadline = None if self._wait_timeout is None else time.monotonic() + self._wait_timeout
        while not any(c not in self._pinned for c in self._idle):
            if deadline is None:
                self._cond.wait()
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            self._cond.wait(remaining)
        return True

    def _new_connection(self) -> AgentConnection:
        """Open one authenticated connection, retrying briefly.

        The agent accepts concurrently, but under load a burst of new sockets
        can transiently fail to complete the hello/auth exchange (observed as
        an occasional ConnectionReset under a 60-thread ramp). One retry with a
        short backoff removes that flakiness without hiding real outages.
        """
        last: Exception | None = None
        for attempt in range(2):
            conn = AgentConnection(self._host, self._port, self._token,
                                   connect_timeout=self._connect_timeout)
            try:
                conn.connect()
                return conn
            except (OSError, TimeoutError, AgentError) as exc:
                last = exc
                try:
                    conn.close()
                except OSError:
                    pass
                if attempt == 0:
                    time.sleep(0.05)
        raise _unavailable(
            f"cannot reach agent at {self._host}:{self._port}: {last}"
        )

    def close(self) -> None:
        with self._cond:
            self._closed = True
            idle, self._idle = self._idle, []
            self._total -= len(idle)
            self._affinity.clear()
            self._cond.notify_all()
        for conn in idle:
            try:
                conn.close()
            except OSError:
                pass
