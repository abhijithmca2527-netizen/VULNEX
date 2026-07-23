from django.db import models
from users.models import User

class Website(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    website_url = models.URLField()
    added_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.website_url