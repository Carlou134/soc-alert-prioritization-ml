from django.contrib import admin
from .models import PredictionLog

@admin.register(PredictionLog)
class PredictionLogAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'predicted_class', 'source', 'created_at')
    list_filter = ('predicted_class', 'source', 'created_at')
    search_fields = ('user__username', 'predicted_class')