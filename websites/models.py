from django.db import models
from users.models import User


# ============================================================
# EXISTING JOWIN MODELS
# ============================================================

class ScanResult(models.Model):
    target_url = models.URLField()
    feature_vector = models.CharField(
        max_length=100
    )
    created_at = models.DateTimeField(
        auto_now_add=True
    )

    def __str__(self):
        return f"{self.target_url} - {self.created_at}"


class SandboxThreat(models.Model):
    """Quarantined scans flagged as anomalies by the Isolation Forest."""

    target_url = models.URLField()
    feature_vector = models.CharField(
        max_length=100
    )

    rf_predicted_risk = models.CharField(
        max_length=50,
        blank=True,
        null=True
    )

    is_approved = models.BooleanField(
        default=False
    )

    verified_risk_level = models.CharField(
        max_length=50,
        blank=True,
        null=True
    )

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    def __str__(self):
        return (
            f"ANOMALY - {self.target_url} "
            f"({self.created_at})"
        )


# ============================================================
# EXISTING SUPABASE TABLE MAPPINGS
# managed=False = Django uses the tables but does not create them
# ============================================================

class Website(models.Model):
    website_id = models.AutoField(
        primary_key=True,
        db_column="website_id"
    )

    user = models.ForeignKey(
        User,
        on_delete=models.DO_NOTHING,
        db_column="user_id",
        related_name="websites"
    )

    website_name = models.CharField(
        max_length=100
    )

    website_url = models.CharField(
        max_length=255
    )

    added_date = models.DateTimeField(
        auto_now_add=True
    )

    class Meta:
        managed = False
        db_table = "WEBSITES"

    def __str__(self):
        return self.website_url


class Scan(models.Model):
    scan_id = models.AutoField(
        primary_key=True,
        db_column="scan_id"
    )

    website = models.ForeignKey(
        Website,
        on_delete=models.DO_NOTHING,
        db_column="website_id",
        related_name="scans"
    )

    scan_date = models.DateTimeField(
        auto_now_add=True
    )

    security_score = models.IntegerField(
        blank=True,
        null=True
    )

    risk_level = models.CharField(
        max_length=20,
        blank=True,
        null=True
    )

    class Meta:
        managed = False
        db_table = "SCANS"

    def __str__(self):
        return (
            f"{self.website.website_url} - "
            f"{self.scan_date}"
        )


class Vulnerability(models.Model):
    vulnerability_id = models.AutoField(
        primary_key=True,
        db_column="vulnerability_id"
    )

    scan = models.ForeignKey(
        Scan,
        on_delete=models.DO_NOTHING,
        db_column="scan_id",
        related_name="vulnerabilities"
    )

    vulnerability_name = models.CharField(
        max_length=150
    )

    description = models.TextField(
        blank=True,
        null=True
    )

    issue = models.TextField(
        blank=True,
        null=True,
        db_column="issue"
    )

    class Meta:
        managed = False
        db_table = "VULNERABILITIES"

    def __str__(self):
        return self.vulnerability_name


class AIDataset(models.Model):
    dataset_id = models.AutoField(
        primary_key=True,
        db_column="dataset_id"
    )

    vulnerability_name = models.CharField(
        max_length=150
    )

    severity = models.CharField(
        max_length=20,
        blank=True,
        null=True
    )

    description = models.TextField(
        blank=True,
        null=True
    )

    solution = models.TextField(
        blank=True,
        null=True
    )

    owasp_category = models.CharField(
        max_length=100,
        blank=True,
        null=True
    )

    class Meta:
        managed = False
        db_table = "AI_DATASET"

    def __str__(self):
        return self.vulnerability_name


class Report(models.Model):
    report_id = models.AutoField(
        primary_key=True,
        db_column="report_id"
    )

    scan = models.ForeignKey(
        Scan,
        on_delete=models.DO_NOTHING,
        db_column="scan_id",
        related_name="reports"
    )

    report_file = models.CharField(
        max_length=255,
        blank=True,
        default=""
    )

    generated_date = models.DateTimeField(
        auto_now_add=True
    )

    class Meta:
        managed = False
        db_table = "REPORTS"

    def __str__(self):
        return f"Report {self.report_id} - Scan {self.scan_id}"
