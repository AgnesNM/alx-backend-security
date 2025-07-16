import logging
from django.utils.deprecation import MiddlewareMixin
from django.utils import timezone
from django.http import HttpResponseForbidden
from .models import RequestLog, BlockedIP


class IPTrackingMiddleware(MiddlewareMixin):
    """
    Middleware to log IP address, timestamp, and path of every incoming request.
    Also blocks requests from blacklisted IPs.
    """
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.logger = logging.getLogger(__name__)
    
    def process_request(self, request):
        """
        Process incoming request, check if IP is blocked, and log the details.
        """
        # Get the real IP address (handles proxies and load balancers)
        ip_address = self.get_client_ip(request)
        
        # Check if IP is blocked
        if BlockedIP.is_blocked(ip_address):
            self.logger.warning(
                f"Blocked request from IP: {ip_address}, Path: {request.get_full_path()}"
            )
            return HttpResponseForbidden(
                "<h1>403 Forbidden</h1><p>Your IP address has been blocked.</p>",
                content_type="text/html"
            )
        
        # Get the request path
        path = request.get_full_path()
        
        # Get current timestamp
        timestamp = timezone.now()
        
        try:
            # Save to database
            RequestLog.objects.create(
                ip_address=ip_address,
                timestamp=timestamp,
                path=path
            )
            
            # Also log to console/file
            self.logger.info(
                f"Request logged - IP: {ip_address}, Path: {path}, Time: {timestamp}"
            )
            
        except Exception as e:
            # Log error but don't break the request flow
            self.logger.error(f"Failed to log request: {str(e)}")
        
        # Continue processing the request
        return None
    
    def get_client_ip(self, request):
        """
        Get the real client IP address from the request.
        Handles cases where the request goes through proxies or load balancers.
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            # Take the first IP in the chain (the original client)
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        
        return ip or '0.0.0.0'  # Fallback if no IP found
