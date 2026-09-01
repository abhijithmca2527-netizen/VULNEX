from django.db import models

class ScanResult(models.Model):
    target_url = models.URLField()
    feature_vector = models.CharField(max_length=100) # e.g., "[1, 1, 1, 1, 1, 0, 0, 0]"
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.target_url} - {self.created_at}"

class SandboxThreat(models.Model):
    """Quarantined scans flagged as anomalies by the Isolation Forest."""
    target_url = models.URLField()
    feature_vector = models.CharField(max_length=100)
    
    # What the Random Forest guessed this was before the Isolation Forest caught it
    rf_predicted_risk = models.CharField(max_length=50, blank=True, null=True) 
    
    # Admin approval switch (You flip this when you verify the threat)
    is_approved = models.BooleanField(default=False) 
    
    # The actual verified risk level assigned by the Admin after review
    verified_risk_level = models.CharField(max_length=50, blank=True, null=True)
    
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"🚨 ANOMALY - {self.target_url} ({self.created_at})"