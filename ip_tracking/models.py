from django.db import models
from django.utils import timezone


class BlockedIP(models.Model):
    """
    Model to store blocked IP addresses.
    """
    ip_address = models.GenericIPAddressField(
        unique=True,
        verbose_name="IP Address",
        help_text="The IP address to block"
    )
    
    blocked_at = models.DateTimeField(
        default=timezone.now,
        verbose_name="Blocked At",
        help_text="When the IP was blocked"
    )
    
    reason = models.CharField(
        max_length=255,
        blank=True,
        verbose_name="Reason",
        help_text="Reason for blocking this IP"
    )
    
    is_active = models.BooleanField(
        default=True,
        verbose_name="Is Active",
        help_text="Whether the block is currently active"
    )
    
    class Meta:
        ordering = ['-blocked_at']
        verbose_name = "Blocked IP"
        verbose_name_plural = "Blocked IPs"
        indexes = [
            models.Index(fields=['ip_address']),
            models.Index(fields=['is_active']),
        ]
    
    def __str__(self):
        return f"{self.ip_address} - {'Active' if self.is_active else 'Inactive'}"
    
    @classmethod
    def is_blocked(cls, ip_address):
        """
        Check if an IP address is blocked.
        """
        return cls.objects.filter(ip_address=ip_address, is_active=True).exists()
    
    @classmethod
    def block_ip(cls, ip_address, reason=""):
        """
        Block an IP address.
        """
        blocked_ip, created = cls.objects.get_or_create(
            ip_address=ip_address,
            defaults={'reason': reason, 'is_active': True}
        )
        if not created and not blocked_ip.is_active:
            blocked_ip.is_active = True
            blocked_ip.reason = reason
            blocked_ip.blocked_at = timezone.now()
            blocked_ip.save()
        return blocked_ip
    
    @classmethod
    def unblock_ip(cls, ip_address):
        """
        Unblock an IP address.
        """
        try:
            blocked_ip = cls.objects.get(ip_address=ip_address)
            blocked_ip.is_active = False
            blocked_ip.save()
            return True
        except cls.DoesNotExist:
            return False


class RequestLog(models.Model):
    """
    Model to store request logs with IP address, timestamp, and path.
    """
    ip_address = models.GenericIPAddressField(
        verbose_name="IP Address",
        help_text="The IP address of the client making the request"
    )
    
    timestamp = models.DateTimeField(
        default=timezone.now,
        verbose_name="Timestamp",
        help_text="When the request was made"
    )
    
    path = models.CharField(
        max_length=255,
        verbose_name="Request Path",
        help_text="The path that was requested"
    )
    
    class Meta:
        ordering = ['-timestamp']  # Most recent first
        verbose_name = "Request Log"
        verbose_name_plural = "Request Logs"
        indexes = [
            models.Index(fields=['ip_address']),
            models.Index(fields=['timestamp']),
            models.Index(fields=['path']),
        ]
    
    def __str__(self):
        return f"{self.ip_address} - {self.path} - {self.timestamp}"
    
    @classmethod
    def get_recent_logs(cls, limit=100):
        """
        Get the most recent request logs.
        """
        return cls.objects.all()[:limit]
    
    @classmethod
    def get_logs_by_ip(cls, ip_address):
        """
        Get all logs for a specific IP address.
        """
        return cls.objects.filter(ip_address=ip_address)
    
    @classmethod
    def get_logs_by_path(cls, path):
        """
        Get all logs for a specific path.
        """
        return cls.objects.filter(path=path)
