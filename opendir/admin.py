from django.contrib import admin
from django.contrib.auth.admin import GroupAdmin as BaseGroupAdmin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import Group, User
from django.db import models
from django.utils.html import format_html

from unfold.admin import ModelAdmin
from unfold.contrib.filters.admin import ChoicesDropdownFilter, RangeDateFilter
from unfold.decorators import display
from unfold.forms import AdminPasswordChangeForm, UserChangeForm, UserCreationForm
from unfold.widgets import UnfoldAdminTextInputWidget

from opendir.models import Candidate, Classification, PayloadHash, Snapshot


def copy_span(value):
    """Render a URL as NON-clickable, select-all copy text.

    These are live exposed hosts — an accidental click must never navigate the
    operator's browser (and IP) to one. So target URLs are shown as plain,
    selectable text, never as an <a>. Navigation to the admin change form is
    provided by a separate, explicit link column.
    """
    if not value:
        return "—"
    return format_html(
        '<span style="font-family:ui-monospace,SFMono-Regular,Menlo,monospace;'
        'user-select:all;-webkit-user-select:all;word-break:break-all" '
        'title="select to copy — not a link">{}</span>',
        value,
    )

# Colored labels for the classification spectrum — mirrors the public dashboard
# (malicious=red, sensitive=amber, intentional=blue, benign=green).
LABEL_COLORS = {
    "malicious_staging": "danger",
    "sensitive_exposure": "warning",
    "intentional_public": "info",
    "benign_index": "success",
}
STATUS_COLORS = {"pending": "warning", "captured": "success", "error": "danger"}
SERVER_COLORS = {"apache": "info", "nginx": "success"}


class ReadOnlyAdmin(ModelAdmin):
    """Base for the append-only tables: browsable but never editable from admin."""

    def get_readonly_fields(self, request, obj=None):
        return [f.name for f in self.model._meta.fields]

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(Candidate)
class CandidateAdmin(ModelAdmin):
    list_display = ("url_copy", "source", "status_badge", "first_seen", "last_captured_at", "open_link")
    list_display_links = ("open_link",)   # URL is not a link; navigate via the explicit column
    list_filter = (("status", ChoicesDropdownFilter), "source", ("first_seen", RangeDateFilter))
    search_fields = ("url", "dedup_key")
    ordering = ("-first_seen",)
    formfield_overrides = {models.TextField: {"widget": UnfoldAdminTextInputWidget}}

    @display(description="URL (copy — not a link)", ordering="url")
    def url_copy(self, obj):
        return copy_span(obj.url)

    @display(description="")
    def open_link(self, obj):
        return "open ↗"

    @display(description="Status", label=STATUS_COLORS, ordering="status")
    def status_badge(self, obj):
        return obj.status


@admin.register(Snapshot)
class SnapshotAdmin(ReadOnlyAdmin):
    list_display = ("cand_url", "fetched_at", "http_status", "server_badge", "is_open_dir", "entry_count", "open_link")
    list_display_links = ("open_link",)   # candidate URL is not a link; navigate via the explicit column
    list_select_related = ("candidate",)
    list_filter = ("server_kind", "is_open_dir", "http_status", ("fetched_at", RangeDateFilter))
    search_fields = ("candidate__url", "title")
    ordering = ("-fetched_at",)

    @display(description="Candidate URL (copy — not a link)", ordering="candidate__url")
    def cand_url(self, obj):
        return copy_span(obj.candidate.url)

    @display(description="")
    def open_link(self, obj):
        return "open ↗"

    @display(description="Server", label=SERVER_COLORS, ordering="server_kind")
    def server_badge(self, obj):
        return obj.server_kind or "unknown"


@admin.register(Classification)
class ClassificationAdmin(ReadOnlyAdmin):
    list_display = ("snapshot", "label_badge", "confidence", "ruleset_version", "classified_at")
    list_filter = (("label", ChoicesDropdownFilter), "ruleset_version", ("classified_at", RangeDateFilter))
    search_fields = ("snapshot__candidate__url",)
    ordering = ("-classified_at",)

    @display(description="Label", label=LABEL_COLORS, ordering="label")
    def label_badge(self, obj):
        return obj.label


@admin.register(PayloadHash)
class PayloadHashAdmin(ReadOnlyAdmin):
    list_display = ("snapshot", "name", "sha256", "size", "vt_badge", "hashed_at")
    list_filter = (("hashed_at", RangeDateFilter),)
    search_fields = ("name", "sha256", "md5")
    ordering = ("-hashed_at",)

    @display(
        description="VirusTotal",
        label={"flagged": "danger", "clean": "success", "pending": "info", "error": "warning"},
    )
    def vt_badge(self, obj):
        if obj.error:
            return "error"
        vt = obj.vt or {}
        if not vt or not vt.get("found"):
            return "pending"
        return "flagged" if vt.get("malicious", 0) else "clean"


# --- Re-register the built-in auth models with Unfold's classes/forms -------
# Without this, /admin/auth/user/<id>/change/ renders bare inputs and loses the
# password-change link (django.contrib.auth registers stock admin classes).
admin.site.unregister(User)
admin.site.unregister(Group)


@admin.register(User)
class UserAdmin(BaseUserAdmin, ModelAdmin):
    form = UserChangeForm
    add_form = UserCreationForm
    change_password_form = AdminPasswordChangeForm


@admin.register(Group)
class GroupAdmin(BaseGroupAdmin, ModelAdmin):
    pass
