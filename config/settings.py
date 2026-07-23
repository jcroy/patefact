import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()
BASE_DIR = Path(__file__).resolve().parent.parent

# Local-dev defaults, all overridable by env. DEBUG defaults ON for the
# documented local workflow; set DJANGO_DEBUG=0 to turn it off.
DEBUG = os.environ.get("DJANGO_DEBUG", "1").lower() not in ("0", "false", "no", "")

# Dev gets a convenient default key; with DEBUG off (i.e. any real deployment)
# a SECRET_KEY must be supplied explicitly rather than shipping a known one.
SECRET_KEY = os.environ.get("SECRET_KEY") or ("dev-insecure-key" if DEBUG else "")
if not SECRET_KEY:
    from django.core.exceptions import ImproperlyConfigured
    raise ImproperlyConfigured("Set the SECRET_KEY environment variable when DJANGO_DEBUG is off.")

# Comma-separated; defaults to "*" for local use.
ALLOWED_HOSTS = [h.strip() for h in os.environ.get("DJANGO_ALLOWED_HOSTS", "*").split(",") if h.strip()]

INSTALLED_APPS = [
    # Unfold admin theme — MUST precede django.contrib.admin (first-app-wins
    # template resolution; wrong order = nothing themed).
    "unfold",
    "unfold.contrib.filters",
    "unfold.contrib.forms",
    "unfold.contrib.inlines",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "opendir",
]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]
ROOT_URLCONF = "config.urls"
TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    "DIRS": [], "APP_DIRS": True,
    "OPTIONS": {"context_processors": [
        "django.template.context_processors.request",   # required by admin sidebar + Unfold
        "django.contrib.auth.context_processors.auth",
        "django.contrib.messages.context_processors.messages",
    ]},
}]
WSGI_APPLICATION = "config.wsgi.application"

_db = os.environ.get("DATABASE_URL", "postgresql://opendir:opendir@localhost:5544/opendir")
from urllib.parse import urlparse
_u = urlparse(_db)
DATABASES = {"default": {
    "ENGINE": "django.db.backends.postgresql",
    "NAME": _u.path.lstrip("/"), "USER": _u.username, "PASSWORD": _u.password,
    "HOST": _u.hostname, "PORT": _u.port or 5544,
}}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
STATIC_URL = "static/"
USE_TZ = True

OPENDIR_CONTACT = os.environ.get("OPENDIR_CONTACT") or "set-OPENDIR_CONTACT-env-var"

OPENDIR_BLOCKED_SUFFIXES = (".gov", ".mil", ".localhost", ".local", ".internal")   # extend as needed; health can't be TLD-matched
OPENDIR_BLOCKED_CIDRS = ()                     # extra IP/CIDR ranges (private ranges always blocked)

OPENDIR_MIN_INTERVAL = float(os.environ.get("OPENDIR_MIN_INTERVAL", "1.0"))

VT_API_KEY = os.environ.get("VT_API_KEY") or ""

# --- Unfold admin theme -----------------------------------------------------
# Branding echoes the public dashboard: warm near-black + amber (#f2a63b).
# Amber primary ramp expressed in oklch (the format Unfold 0.101 expects).
from django.urls import reverse_lazy  # noqa: E402

UNFOLD = {
    "SITE_TITLE": "patefact admin",
    "SITE_HEADER": "patefact",
    "SITE_SUBHEADER": "open-directory observatory",
    "SITE_SYMBOL": "travel_explore",          # Material Symbols icon (no static asset needed)
    "SITE_URL": None,                          # no public site to link back to
    "SHOW_HISTORY": True,
    "SHOW_VIEW_ON_SITE": False,
    "SHOW_BACK_BUTTON": True,
    "THEME": None,                             # keep the light/dark switcher
    "BORDER_RADIUS": "5px",
    "ENVIRONMENT": "opendir.admin_theme.environment_callback",
    "COLORS": {
        "primary": {
            "50":  "oklch(97.5% .02 75)",
            "100": "oklch(94.5% .045 74)",
            "200": "oklch(89% .085 72)",
            "300": "oklch(83% .12 70)",
            "400": "oklch(78% .145 68)",
            "500": "oklch(72.5% .155 66)",     # ~#f2a63b, the brand amber
            "600": "oklch(64% .15 60)",
            "700": "oklch(55% .13 55)",        # ~#b9821f
            "800": "oklch(46% .11 52)",
            "900": "oklch(38% .09 50)",
            "950": "oklch(27% .065 48)",
        },
    },
    "SIDEBAR": {
        "show_search": True,
        "show_all_applications": True,
        "navigation": [
            {
                "title": "Pipeline",
                "separator": True,
                "collapsible": False,   # keep groups expanded by default
                "items": [
                    {
                        "title": "Candidates",
                        "icon": "dns",
                        "link": reverse_lazy("admin:opendir_candidate_changelist"),
                        "badge": "opendir.admin_theme.pending_candidates_badge",
                    },
                    {
                        "title": "Snapshots",
                        "icon": "photo_camera",
                        "link": reverse_lazy("admin:opendir_snapshot_changelist"),
                    },
                    {
                        "title": "Classifications",
                        "icon": "category",
                        "link": reverse_lazy("admin:opendir_classification_changelist"),
                    },
                    {
                        "title": "Payload hashes",
                        "icon": "fingerprint",
                        "link": reverse_lazy("admin:opendir_payloadhash_changelist"),
                    },
                ],
            },
            {
                "title": "Access",
                "separator": True,
                "collapsible": False,   # keep groups expanded by default
                "items": [
                    {
                        "title": "Users",
                        "icon": "person",
                        "link": reverse_lazy("admin:auth_user_changelist"),
                        "permission": lambda request: request.user.is_superuser,
                    },
                    {
                        "title": "Groups",
                        "icon": "group",
                        "link": reverse_lazy("admin:auth_group_changelist"),
                        "permission": lambda request: request.user.is_superuser,
                    },
                ],
            },
        ],
    },
}
