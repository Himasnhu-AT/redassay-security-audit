"""VULN pack: exposure. Not a real service."""

import logging
import traceback

log = logging.getLogger(__name__)


def authenticate(username, password):
    # VULN: expose.credential-logged
    log.info("login attempt user=%s password=%s", username, password)
    return check(username, password)


def handle_error(exc):
    # VULN: expose.stack-trace-rendered
    return render("error.html", detail=traceback.format_exc())


def promote(actor, target):
    # VULN: expose.no-audit-on-privileged-action
    grant_admin(target)
    return {"ok": True}


def check(username, password):
    raise NotImplementedError


def render(*args, **kwargs):
    raise NotImplementedError


def grant_admin(user):
    raise NotImplementedError
