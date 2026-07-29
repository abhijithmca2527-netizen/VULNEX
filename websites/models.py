from django.db import models

class ScanResult(models.Model):
    target_url = models.URLField()
    feature_vector = models.CharField(max_length=100) # e.g., "[1, 1, 1, 1, 1, 0, 0, 0]"
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.target_url} - {self.created_at}"