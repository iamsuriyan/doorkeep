"""Verify doorkeep tokens from a Python backend (standard library only).

    from doorkeep import Verifier
    dk = Verifier("http://127.0.0.1:8080", os.environ["DOORKEEP_SECRET"])
    result = dk.verify(request.POST.get("dk-response", ""), action="signup", remote_ip=ip)
    if not result.success:
        ...refuse...
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Optional

__all__ = ["Verifier", "VerifyResult", "DoorkeepUnavailable"]


class DoorkeepUnavailable(Exception):
    """doorkeep could not be reached (or did not answer like doorkeep)."""


@dataclass
class VerifyResult:
    success: bool
    error_codes: list = field(default_factory=list)
    action: str = ""
    hostname: str = ""
    score: Optional[float] = None
    risk: Optional[int] = None
    outcome: str = ""
    reasons: list = field(default_factory=list)
    event_id: str = ""
    failed_open: bool = False
    raw: dict = field(default_factory=dict)


class Verifier:
    def __init__(self, endpoint: str, secret: str, fail_open: bool = False, timeout: float = 3.0):
        self.endpoint = endpoint.rstrip("/")
        self.secret = secret
        self.fail_open = fail_open
        self.timeout = timeout

    def _post(self, path: str, form: dict) -> dict:
        data = urllib.parse.urlencode(form).encode()
        req = urllib.request.Request(self.endpoint + path, data=data, method="POST",
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as res:
                body = res.read(1 << 20)
        except urllib.error.HTTPError as e:
            if e.code >= 500:
                raise DoorkeepUnavailable(f"HTTP {e.code}") from e
            body = e.read(1 << 20)
        except (urllib.error.URLError, OSError) as e:
            raise DoorkeepUnavailable(str(e)) from e
        try:
            out = json.loads(body)
        except ValueError as e:
            raise DoorkeepUnavailable("response is not JSON: " + body[:80].decode(errors="replace")) from e
        if not isinstance(out, dict):
            raise DoorkeepUnavailable("unexpected response")
        return out

    def verify(self, response: str, action: str = "", hostname: str = "", remote_ip: str = "") -> VerifyResult:
        """Check a token. A missing token is a failed check, not an error."""
        if not response:
            return VerifyResult(success=False, error_codes=["missing-input-response"])
        form: dict[str, Any] = {"secret": self.secret, "response": response}
        if action:
            form["expected_action"] = action
        if hostname:
            form["expected_hostname"] = hostname
        if remote_ip:
            form["remoteip"] = remote_ip
        try:
            j = self._post("/v1/siteverify", form)
            if not isinstance(j.get("success"), bool):
                raise DoorkeepUnavailable("unexpected response")
        except DoorkeepUnavailable:
            if self.fail_open:
                return VerifyResult(success=True, failed_open=True)
            raise
        dk = j.get("doorkeep") or {}
        return VerifyResult(
            success=j["success"], error_codes=j.get("error-codes") or [], action=j.get("action", ""),
            hostname=j.get("hostname", ""), score=j.get("score"), risk=dk.get("risk"), outcome=dk.get("outcome", ""),
            reasons=dk.get("reasons") or [], event_id=dk.get("event_id", ""), raw=j,
        )

    def report(self, event_id: str, bot: bool) -> bool:
        """Label an event so the site's model learns your ground truth."""
        j = self._post("/v1/report", {"secret": self.secret, "event_id": event_id, "label": "bot" if bot else "human"})
        return bool(j.get("success"))
