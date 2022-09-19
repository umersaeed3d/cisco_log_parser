from django.utils.timezone import now
from django.db import models

# Create your models here.
class CiscoLogs(models.Model):
    id = models.AutoField(primary_key=True)
    input_file = models.CharField(max_length=255)
    user_id = models.IntegerField()
    timestamp = models.DateTimeField(auto_now_add=True)
    class Meta:
        db_table = 'cisco_logs'
