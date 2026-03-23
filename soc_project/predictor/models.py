from django.db import models
from django.contrib.auth.models import User

class PredictionLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    input_data = models.JSONField()
    predicted_class = models.CharField(max_length=100)
    probabilities = models.JSONField(null=True, blank=True)
    source = models.CharField(max_length=20, default='manual')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.predicted_class} - {self.created_at:%Y-%m-%d %H:%M}"