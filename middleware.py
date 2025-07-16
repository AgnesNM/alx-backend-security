import logging
from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin
from .models import RequestLog

logger = logging.getLogger(__name__)

class IPTrackingMiddleware(MiddlewareMixin):
    """
    Middleware to log IP address, timestamp, and path of every incoming request.
    """
    
    def process_request(self, request):
        """
        Process incoming request and log details to database.
        """
        # Get client IP address (handles proxy/load balancer scenarios)
        ip_address = self.get_client_ip(request)
        
        # Get request path
        path = request.get_full_path()
        
        # Get current timestamp
        timestamp = timezone.now()
        
        try:
            # Create log entry in database
            RequestLog.objects.create(
                ip_address=ip_address,
                timestamp=timestamp,
                path=path
            )
            
            # Also log to Django's logging system
            logger.info(f"Request logged: IP={ip_address}, Path={path}, Time={timestamp}")
            
        except Exception as e:
            # Log error but don't break the request processing
            logger.error(f"Failed to log request: {str(e)}")
        
        # Return None to continue processing the request
        return None
    
    def get_client_ip(self, request):
        """
        Get the client's IP address, handling proxies and load balancers.
        """
        # Check for IP in X-Forwarded-For header (common with proxies/load balancers)
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            # X-Forwarded-For can contain multiple IPs, take the first one
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            # Fall back to REMOTE_ADDR
            ip = request.META.get('REMOTE_ADDR')
        
        return ip or 'unknown'
