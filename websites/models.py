from django.db import models

class Website(models.Model):
    website_id = models.BigAutoField(primary_key=True)
    url = models.URLField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'WEBSITES'
        managed = False

    def __str__(self):
        return self.url


class ScanResult(models.Model):
    scan_id = models.BigAutoField(primary_key=True)
    scan_date = models.DateTimeField(auto_now_add=True)
    security_score = models.IntegerField(null=True, blank=True)
    risk_level = models.CharField(max_length=100, null=True, blank=True)
    website_id = models.IntegerField()

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