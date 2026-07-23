"""Callbacks for the Unfold admin theme (referenced by string in UNFOLD settings)."""
from django.conf import settings


def environment_callback(request):
    """Badge in the header distinguishing dev from prod. (label, color)."""
    if settings.DEBUG:
        return ["Development", "warning"]
    return ["Production", "success"]


def pending_candidates_badge(request):
    """Sidebar badge: number of candidates still awaiting capture (hidden if 0)."""
    try:
        from opendir.models import Candidate
        n = Candidate.objects.filter(status="pending").count()
        return str(n) if n else None
    except Exception:
        return None
