"""{% load doorkeep %} ... {% doorkeep "signup" %} inside a <form>."""

from django import template
from django.conf import settings
from django.utils.html import format_html

register = template.Library()


@register.simple_tag
def doorkeep(action: str = "default", src: str = "/_dk/v1/dk.js"):
    key = getattr(settings, "DOORKEEP", {}).get("SITE_KEY", "")
    return format_html('<script src="{}" data-sitekey="{}" async defer></script><div class="doorkeep" data-action="{}"></div>', src, key, action)
