"""Django helpers.

settings.py:
    DOORKEEP = {"URL": "http://127.0.0.1:8080", "SECRET": env("DOORKEEP_SECRET"),
                "SITE_KEY": "dk_pk_...", "FAIL_OPEN": False}
    INSTALLED_APPS += ["doorkeep"]          # for the {% doorkeep %} template tag

Forms:
    class SignupForm(DoorkeepFormMixin, forms.Form):
        doorkeep_action = "signup"
        ...
    form = SignupForm(request.POST, request=request)

Views:
    @require_doorkeep(action="signup")
    def signup(request): ...       # request.doorkeep holds the result
"""

from __future__ import annotations

import functools
from typing import Optional

from django import forms
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponseForbidden

from . import DoorkeepUnavailable, Verifier, VerifyResult

FIELD = "dk-response"
MESSAGE = "We could not verify this request. Please try again."

_verifier: Optional[Verifier] = None


def get_verifier() -> Verifier:
    global _verifier
    if _verifier is None:
        c = getattr(settings, "DOORKEEP", {})
        if not c.get("SECRET"):
            raise ImproperlyConfigured("set DOORKEEP['SECRET']")
        _verifier = Verifier(c.get("URL", "http://127.0.0.1:8080"), c["SECRET"], bool(c.get("FAIL_OPEN", False)), float(c.get("TIMEOUT", 3)))
    return _verifier


def client_ip(request) -> str:
    """REMOTE_ADDR. Behind a proxy, set it from X-Forwarded-For in middleware you trust."""
    return request.META.get("REMOTE_ADDR", "") if request is not None else ""


def check(request, action: str = "") -> VerifyResult:
    """Verify the token in request.POST. Unavailable doorkeep counts as a failed check."""
    try:
        return get_verifier().verify(request.POST.get(FIELD, ""), action=action, remote_ip=client_ip(request))
    except DoorkeepUnavailable:
        return VerifyResult(success=False, error_codes=["unavailable"])


class DoorkeepFormMixin:
    """Adds the doorkeep check to a form's clean(). Pass request=request."""

    doorkeep_action = ""

    def __init__(self, *args, request=None, **kwargs):
        self.request = request
        self.doorkeep: Optional[VerifyResult] = None
        super().__init__(*args, **kwargs)

    def clean(self):
        cleaned = super().clean()
        token = self.data.get(FIELD, "") if self.data is not None else ""
        try:
            self.doorkeep = get_verifier().verify(token, action=self.doorkeep_action, remote_ip=client_ip(self.request))
        except DoorkeepUnavailable:
            self.doorkeep = VerifyResult(success=False, error_codes=["unavailable"])
        if not self.doorkeep.success:
            raise forms.ValidationError(MESSAGE, code="doorkeep")
        return cleaned


def require_doorkeep(action: str = ""):
    """View decorator: POST requests must carry a valid token."""

    def deco(view):
        @functools.wraps(view)
        def wrapped(request, *args, **kwargs):
            if request.method == "POST":
                request.doorkeep = check(request, action)
                if not request.doorkeep.success:
                    return HttpResponseForbidden(MESSAGE)
            return view(request, *args, **kwargs)

        return wrapped

    return deco
