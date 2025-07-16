from django.db import models
from django.utils import timezone

class RequestLog(models.Model):
    """
    Model to store request logging information including IP address, timestamp, and path.
    """
    
    ip_address = models.GenericIPAddressField(
        help_text="IP address of the client making the request",
        db_index=True  # Index for faster queries
    )
    
    timestamp = models.DateTimeField(
        default=timezone.now,
        help_text="When the request was made",
        db_index=True  # Index for faster time-based queries
    )
    
    path = models.TextField(
        help_text="The full path of the request including query parameters",
        db_index=True  # Index for faster path-based queries
    )
    
    class Meta:
        db_table = 'request_logs'
        ordering = ['-timestamp']  # Most recent first
        indexes = [
            models.Index(fields=['ip_address', 'timestamp']),
            models.Index(fields=['path', 'timestamp']),
        ]
        verbose_name = "Request Log"
        verbose_name_plural = "Request Logs"
    
    def __str__(self):
        return f"{self.ip_address} - {self.path} - {self.timestamp}"
    
    def save(self, *args, **kwargs):
        """
        Override save method to ensure timestamp is set if not provided.
        """
        if not self.timestamp:
            self.timestamp = timezone.now()
        super().save(*args, **kwargs)
