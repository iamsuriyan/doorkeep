# doorkeep for Python and Django

Standard-library client, plus Django form, view and template helpers.

```sh
pip install doorkeep            # client only
pip install "doorkeep[django]"
```

```python
from doorkeep import Verifier
dk = Verifier("http://127.0.0.1:8080", os.environ["DOORKEEP_SECRET"])
r = dk.verify(token, action="signup", remote_ip=ip)
if not r.success: ...
```

Django (`settings.py`):

```python
DOORKEEP = {"URL": "http://127.0.0.1:8080", "SECRET": os.environ["DOORKEEP_SECRET"], "SITE_KEY": "dk_pk_..."}
INSTALLED_APPS += ["doorkeep"]
```

Template, inside the form: `{% load doorkeep %}{% doorkeep "signup" %}`.

Then a form mixin (`SignupForm(DoorkeepFormMixin, forms.Form)` with
`doorkeep_action = "signup"`, constructed with `request=request`) or a view
decorator (`@require_doorkeep(action="signup")`). The verify result is on
`form.doorkeep` or `request.doorkeep`. doorkeep being unreachable counts as a
failed check unless `"FAIL_OPEN": True`.
