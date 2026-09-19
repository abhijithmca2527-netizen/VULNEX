from django.db import models


class User(models.Model):

    id = models.AutoField(
        primary_key=True,
        db_column="user_id"
    )

    full_name = models.CharField(
        max_length=100
    )

    email = models.EmailField(
        unique=True
    )

    mobile_number = models.CharField(
        max_length=15,
        unique=True
    )

    password = models.CharField(
        max_length=255
    )

    otp_verified = models.BooleanField(
        default=False
    )

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    class Meta:
        db_table = "USERS"
        managed = False

    def __str__(self):
        return self.full_name