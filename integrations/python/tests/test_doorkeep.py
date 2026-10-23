"""Run: uv run --with django --with-editable . python -m unittest discover -s tests"""

import http.server
import json
import threading
import unittest
import urllib.parse

import django
from django.conf import settings

seen = {}


class FakeDoorkeep(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        form = dict(urllib.parse.parse_qsl(self.rfile.read(int(self.headers["Content-Length"])).decode()))
        seen.clear()
        seen.update(form, path=self.path)
        if self.path.startswith("/down"):
            self.send_response(503)
            self.end_headers()
            return
        if self.path.startswith("/html"):
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"<html>nope</html>")
            return
        ok = form.get("response") == "good"
        body = {"success": ok, "error-codes": [] if ok else ["invalid-input-response"], "action": form.get("expected_action", ""),
                "doorkeep": {"risk": 3 if ok else 90, "outcome": "allow" if ok else "block", "reasons": [], "event_id": "evt_1"}}
        if self.path.endswith("/v1/report"):
            body = {"success": True, "error-codes": []}
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())


srv = http.server.HTTPServer(("127.0.0.1", 0), FakeDoorkeep)
threading.Thread(target=srv.serve_forever, daemon=True).start()
BASE = f"http://127.0.0.1:{srv.server_port}"

settings.configure(
    DOORKEEP={"URL": BASE, "SECRET": "dk_sk_test", "SITE_KEY": "dk_pk_test"},
    INSTALLED_APPS=["doorkeep"],
    TEMPLATES=[{"BACKEND": "django.template.backends.django.DjangoTemplates", "APP_DIRS": True}],
    ROOT_URLCONF=__name__,
    ALLOWED_HOSTS=["*"],
)
django.setup()
urlpatterns = []

from django import forms  # noqa: E402
from django.template import Context, Template  # noqa: E402
from django.test import RequestFactory  # noqa: E402

import doorkeep.django as dj  # noqa: E402
from doorkeep import DoorkeepUnavailable, Verifier  # noqa: E402


class SignupForm(dj.DoorkeepFormMixin, forms.Form):
    doorkeep_action = "signup"
    email = forms.EmailField()


class ClientTest(unittest.TestCase):
    def test_verify(self):
        r = Verifier(BASE, "s").verify("good", action="signup", remote_ip="203.0.113.5")
        self.assertTrue(r.success)
        self.assertEqual(r.risk, 3)
        self.assertEqual((seen["expected_action"], seen["remoteip"], seen["path"]), ("signup", "203.0.113.5", "/v1/siteverify"))
        self.assertFalse(Verifier(BASE, "s").verify("bad").success)
        self.assertEqual(Verifier(BASE, "s").verify("").error_codes, ["missing-input-response"])

    def test_unavailable(self):
        for path in ("/down", "/html"):
            with self.assertRaises(DoorkeepUnavailable):
                Verifier(BASE + path, "s").verify("t")
            r = Verifier(BASE + path, "s", fail_open=True).verify("t")
            self.assertTrue(r.success and r.failed_open)
        with self.assertRaises(DoorkeepUnavailable):
            Verifier("http://127.0.0.1:1", "s", timeout=1).verify("t")

    def test_report(self):
        self.assertTrue(Verifier(BASE, "s").report("evt_1", bot=True))
        self.assertEqual(seen["label"], "bot")


class DjangoTest(unittest.TestCase):
    rf = RequestFactory()

    def test_form(self):
        ok = SignupForm({"email": "a@example.com", "dk-response": "good"}, request=self.rf.post("/", REMOTE_ADDR="198.51.100.4"))
        self.assertTrue(ok.is_valid(), ok.errors)
        self.assertEqual(seen["remoteip"], "198.51.100.4")
        self.assertEqual(seen["expected_action"], "signup")
        bad = SignupForm({"email": "a@example.com", "dk-response": "bad"}, request=self.rf.post("/"))
        self.assertFalse(bad.is_valid())
        self.assertIn(dj.MESSAGE, bad.non_field_errors())
        self.assertFalse(SignupForm({"email": "a@example.com"}).is_valid())

    def test_decorator(self):
        @dj.require_doorkeep(action="signup")
        def view(request):
            from django.http import HttpResponse
            return HttpResponse("created")

        self.assertEqual(view(self.rf.post("/", {"dk-response": "good"})).status_code, 200)
        self.assertEqual(view(self.rf.post("/", {"dk-response": "bad"})).status_code, 403)
        self.assertEqual(view(self.rf.post("/", {})).status_code, 403)
        self.assertEqual(view(self.rf.get("/")).status_code, 200)

    def test_template_tag(self):
        html = Template('{% load doorkeep %}{% doorkeep "signup" %}').render(Context())
        self.assertIn('data-sitekey="dk_pk_test"', html)
        self.assertIn('data-action="signup"', html)


if __name__ == "__main__":
    unittest.main()
