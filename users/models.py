from django.db import models

class User(models.Model):
    user_id = models.BigAutoField(primary_key=True)  # Maps to Supabase's user_id column
    full_name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    mobile_number = models.CharField(max_length=15, unique=True)
    password = models.CharField(max_length=255)
    otp_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'USERS'  # Forces Django to use the cloud table name
        managed = False     # Tells Django not to try modifying this table during migrations

    def __str__(self):
        return self.full_name