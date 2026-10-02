from django.db import models
from users.models import User

class Website(models.Model):
    website_id = models.BigAutoField(primary_key=True)
    website_name = models.CharField(max_length=255, null=True, blank=True)
    website_url = models.URLField(max_length=255, unique=True)
    added_date = models.DateTimeField(auto_now_add=True)
    user_id = models.IntegerField(null=True, blank=True)

    class Meta:
        db_table = 'WEBSITES'
        managed = False

    def __str__(self):
        return self.website_url


class ScanResult(models.Model):
    scan_id = models.BigAutoField(primary_key=True)
    scan_date = models.DateTimeField(auto_now_add=True)
    security_score = models.IntegerField(null=True, blank=True)
    risk_level = models.CharField(max_length=100, null=True, blank=True)
    website_id = models.IntegerField()

    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        db_column="user_id",
        related_name="performed_scans"
    )
    @property
    def website(self):
        return Website.objects.filter(
            website_id=self.website_id
        ).first()

    class Meta:
        db_table = 'SCANS'
        managed = False

    def __str__(self):
        return f"Scan {self.scan_id} - Score: {self.security_score} - {self.risk_level}"


class SandboxThreat(models.Model):
    threat_id = models.BigAutoField(primary_key=True)
    target_url = models.URLField()
    feature_vector = models.CharField(max_length=100)
    rf_predicted_risk = models.CharField(max_length=50, blank=True, null=True)
    is_approved = models.BooleanField(default=False)
    verified_risk_level = models.CharField(max_length=50, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'SANDBOX_THREATS'
        managed = False

    def __str__(self):
        return f"🚨 ANOMALY - {self.target_url} ({self.created_at})"

class Vulnerability(models.Model):
    vulnerability_id = models.BigAutoField(primary_key=True)
    vulnerability_name = models.CharField(max_length=255)
    description = models.TextField()
    scan = models.ForeignKey(
        ScanResult,
        on_delete=models.DO_NOTHING,
        db_column="scan_id",
        related_name="vulnerabilities",
    )
    issue = models.TextField(null=True, blank=True)

    class Meta:
        db_table = 'VULNERABILITIES'
        managed = False