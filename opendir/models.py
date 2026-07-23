from django.db import models


class Candidate(models.Model):
    STATUS = [("pending", "pending"), ("captured", "captured"), ("error", "error")]
    dedup_key = models.CharField(max_length=1024, unique=True)
    url = models.TextField()
    source = models.CharField(max_length=64)
    source_meta = models.JSONField(default=dict, blank=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=16, choices=STATUS, default="pending")
    last_captured_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.url


class Snapshot(models.Model):
    candidate = models.ForeignKey(Candidate, on_delete=models.CASCADE, related_name="snapshots")
    fetched_at = models.DateTimeField(auto_now_add=True)
    http_status = models.IntegerField(null=True, blank=True)
    final_url = models.TextField(blank=True, default="")
    headers = models.JSONField(default=list, blank=True)
    server_banner = models.CharField(max_length=512, blank=True, default="")
    server_kind = models.CharField(max_length=32, blank=True, default="unknown")
    title = models.CharField(max_length=512, blank=True, default="")
    is_open_dir = models.BooleanField(default=False)
    listing_entries = models.JSONField(default=list, blank=True)
    entry_count = models.IntegerField(default=0)
    raw_html_sha256 = models.CharField(max_length=64, blank=True, default="")
    header_order_sha256 = models.CharField(max_length=64, blank=True, default="")
    template_sha256 = models.CharField(max_length=64, blank=True, default="")
    favicon_sha256 = models.CharField(max_length=64, null=True, blank=True)
    tls = models.JSONField(null=True, blank=True)
    error = models.TextField(blank=True, default="")

    class Meta:
        indexes = [models.Index(fields=["candidate", "fetched_at"])]

    def __str__(self):
        return f"snapshot<{self.candidate_id}@{self.fetched_at:%Y-%m-%d}>"


class Classification(models.Model):
    """Append-only classification result for a Snapshot.

    Reclassifying (e.g. after a ruleset bump) creates a NEW row rather than
    updating an existing one, so history is preserved. Dedup by
    (snapshot, ruleset_version) is enforced at the query layer (see the
    ``classify`` management command), not via a DB constraint.
    """

    snapshot = models.ForeignKey(Snapshot, on_delete=models.CASCADE, related_name="classifications")
    label = models.CharField(max_length=32)
    confidence = models.FloatField()
    reasons = models.JSONField(default=list, blank=True)
    features = models.JSONField(default=dict, blank=True)
    extractor_version = models.CharField(max_length=16)
    ruleset_version = models.CharField(max_length=16)
    classified_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"classification<{self.snapshot_id}:{self.label}>"


class PayloadHash(models.Model):
    """Append-only hash record for a single allowlisted payload file fetched
    from a flagged (sensitive/malicious) Snapshot's listing.

    Only executables/scripts selected by ``opendir.payload.select`` are ever
    hashed -- media/archive/document/data files are never downloaded, so
    this table cannot contain hashes of CSAM/PII content. ``vt`` is filled
    in by a later VirusTotal-lookup task; it is null until then.
    """

    snapshot = models.ForeignKey(Snapshot, on_delete=models.CASCADE, related_name="payload_hashes")
    name = models.CharField(max_length=512)
    url = models.TextField()
    sha256 = models.CharField(max_length=64, blank=True, default="")
    md5 = models.CharField(max_length=32, blank=True, default="")
    tlsh = models.CharField(max_length=80, blank=True, default="")  # TLSH is 72 chars (T1 prefix + 70 hex)
    size = models.BigIntegerField(default=0)
    error = models.TextField(blank=True, default="")
    vt = models.JSONField(null=True, blank=True)
    hashed_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"payloadhash<{self.snapshot_id}:{self.name}>"
