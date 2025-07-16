import logging
from datetime import datetime, timedelta
from django.utils import timezone
from django.db.models import Count, Q
from django.conf import settings
from celery import shared_task
from .models import RequestLog, SuspiciousIP, BlockedIP


logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3)
def detect_anomalies(self):
    """
    Celery task to detect anomalous IP behavior.
    Runs hourly to analyze request patterns and flag suspicious IPs.
    """
    try:
        logger.info("Starting anomaly detection task")
        
        # Get the time window for analysis (last hour)
        end_time = timezone.now()
        start_time = end_time - timedelta(hours=1)
        
        # Get request logs from the last hour
        recent_logs = RequestLog.objects.filter(
            timestamp__gte=start_time,
            timestamp__lt=end_time
        )
        
        logger.info(f"Analyzing {recent_logs.count()} requests from the last hour")
        
        # Run different anomaly detection checks
        results = {
            'high_volume_ips': detect_high_volume_ips(recent_logs),
            'sensitive_path_access': detect_sensitive_path_access(recent_logs),
            'rapid_fire_requests': detect_rapid_fire_requests(recent_logs),
            'suspicious_patterns': detect_suspicious_patterns(recent_logs),
            'geographic_anomalies': detect_geographic_anomalies(recent_logs),
        }
        
        # Log results
        total_flagged = sum(len(result) for result in results.values())
        logger.info(f"Anomaly detection completed. Total IPs flagged: {total_flagged}")
        
        # Send notifications for critical flags
        send_anomaly_notifications(results)
        
        return {
            'status': 'success',
            'timestamp': end_time.isoformat(),
            'analysis_period': f"{start_time.isoformat()} - {end_time.isoformat()}",
            'total_requests_analyzed': recent_logs.count(),
            'results': {key: len(value) for key, value in results.items()},
            'flagged_ips': total_flagged
        }
        
    except Exception as exc:
        logger.error(f"Anomaly detection task failed: {str(exc)}")
        raise self.retry(exc=exc, countdown=60)


def detect_high_volume_ips(recent_logs):
    """
    Detect IPs with unusually high request volume (>100 requests/hour).
    """
    flagged_ips = []
    
    # Count requests per IP
    ip_counts = recent_logs.values('ip_address').annotate(
        request_count=Count('id')
    ).filter(request_count__gt=100)
    
    for ip_data in ip_counts:
        ip_address = ip_data['ip_address']
        request_count = ip_data['request_count']
        
        # Skip if already flagged recently
        if SuspiciousIP.objects.filter(
            ip_address=ip_address,
            flagged_at__gte=timezone.now() - timedelta(hours=1)
        ).exists():
            continue
        
        # Determine severity based on request count
        if request_count > 500:
            severity = 'CRITICAL'
        elif request_count > 300:
            severity = 'HIGH'
        else:
            severity = 'MEDIUM'
        
        reason = f"High volume activity: {request_count} requests in the last hour"
        
        suspicious_ip = SuspiciousIP.flag_ip(
            ip_address=ip_address,
            reason=reason,
            request_count=request_count,
            severity=severity,
            auto_block=(severity == 'CRITICAL')
        )
        
        flagged_ips.append(suspicious_ip)
        logger.warning(f"Flagged high volume IP: {ip_address} ({request_count} requests)")
    
    return flagged_ips


def detect_sensitive_path_access(recent_logs):
    """
    Detect IPs accessing sensitive paths frequently.
    """
    flagged_ips = []
    
    # Define sensitive paths
    sensitive_paths = [
        '/admin/',
        '/login/',
        '/password-reset/',
        '/api/',
        '/staff/',
        '/management/',
        '/debug/',
        '/phpmyadmin/',
        '/wp-admin/',
        '/xmlrpc.php',
        '/.env',
        '/config/',
        '/backup/',
    ]
    
    # Create Q objects for sensitive path filtering
    sensitive_path_q = Q()
    for path in sensitive_paths:
        sensitive_path_q |= Q(path__icontains=path)
    
    # Get IPs accessing sensitive paths
    sensitive_access = recent_logs.filter(sensitive_path_q).values('ip_address').annotate(
        request_count=Count('id'),
        paths=Count('path', distinct=True)
    )
    
    for ip_data in sensitive_access:
        ip_address = ip_data['ip_address']
        request_count = ip_data['request_count']
        unique_paths = ip_data['paths']
        
        # Skip if already flagged recently
        if SuspiciousIP.objects.filter(
            ip_address=ip_address,
            flagged_at__gte=timezone.now() - timedelta(hours=1)
        ).exists():
            continue
        
        # Determine severity
        if request_count > 50 or unique_paths > 10:
            severity = 'HIGH'
        elif request_count > 20 or unique_paths > 5:
            severity = 'MEDIUM'
        else:
            severity = 'LOW'
        
        reason = f"Sensitive path access: {request_count} requests to {unique_paths} sensitive paths"
        
        suspicious_ip = SuspiciousIP.flag_ip(
            ip_address=ip_address,
            reason=reason,
            request_count=request_count,
            severity=severity,
            auto_block=(severity == 'HIGH' and request_count > 50)
        )
        
        flagged_ips.append(suspicious_ip)
        logger.warning(f"Flagged sensitive path access: {ip_address} ({request_count} requests)")
    
    return flagged_ips


def detect_rapid_fire_requests(recent_logs):
    """
    Detect IPs making rapid consecutive requests (potential bot behavior).
    """
    flagged_ips = []
    
    # Get IPs with high request frequency
    rapid_ips = recent_logs.values('ip_address').annotate(
        request_count=Count('id')
    ).filter(request_count__gt=50)
    
    for ip_data in rapid_ips:
        ip_address = ip_data['ip_address']
        
        # Get requests for this IP ordered by timestamp
        ip_requests = recent_logs.filter(ip_address=ip_address).order_by('timestamp')
        
        # Check for rapid fire patterns (more than 10 requests in 60 seconds)
        rapid_fire_count = 0
        for i in range(len(ip_requests) - 10):
            time_window = ip_requests[i + 10].timestamp - ip_requests[i].timestamp
            if time_window.total_seconds() <= 60:
                rapid_fire_count += 1
        
        if rapid_fire_count > 5:  # Multiple rapid fire sequences
            # Skip if already flagged recently
            if SuspiciousIP.objects.filter(
                ip_address=ip_address,
                flagged_at__gte=timezone.now() - timedelta(hours=1)
            ).exists():
                continue
            
            severity = 'HIGH' if rapid_fire_count > 20 else 'MEDIUM'
            reason = f"Rapid fire requests: {rapid_fire_count} burst sequences detected"
            
            suspicious_ip = SuspiciousIP.flag_ip(
                ip_address=ip_address,
                reason=reason,
                request_count=ip_data['request_count'],
                severity=severity,
                auto_block=(severity == 'HIGH')
            )
            
            flagged_ips.append(suspicious_ip)
            logger.warning(f"Flagged rapid fire IP: {ip_address} ({rapid_fire_count} sequences)")
    
    return flagged_ips


def detect_suspicious_patterns(recent_logs):
    """
    Detect other suspicious patterns like unusual user agents, etc.
    """
    flagged_ips = []
    
    # Detect IPs with suspicious path patterns
    suspicious_patterns = [
        '/../',  # Directory traversal
        '/etc/passwd',  # System file access
        '/proc/',  # Process information
        'SELECT * FROM',  # SQL injection attempts
        '<script>',  # XSS attempts
        'eval(',  # Code injection
        'base64_decode',  # Suspicious PHP functions
        'cmd=',  # Command injection
        'union select',  # SQL injection
        'or 1=1',  # SQL injection
    ]
    
    for pattern in suspicious_patterns:
        suspicious_requests = recent_logs.filter(path__icontains=pattern)
        
        if suspicious_requests.exists():
            ip_counts = suspicious_requests.values('ip_address').annotate(
                request_count=Count('id')
            )
            
            for ip_data in ip_counts:
                ip_address = ip_data['ip_address']
                request_count = ip_data['request_count']
                
                # Skip if already flagged recently
                if SuspiciousIP.objects.filter(
                    ip_address=ip_address,
                    flagged_at__gte=timezone.now() - timedelta(hours=1)
                ).exists():
                    continue
                
                reason = f"Suspicious pattern detected: '{pattern}' in {request_count} requests"
                
                suspicious_ip = SuspiciousIP.flag_ip(
                    ip_address=ip_address,
                    reason=reason,
                    request_count=request_count,
                    severity='HIGH',
                    auto_block=True
                )
                
                flagged_ips.append(suspicious_ip)
                logger.warning(f"Flagged suspicious pattern: {ip_address} ({pattern})")
    
    return flagged_ips


def detect_geographic_anomalies(recent_logs):
    """
    Detect potential geographic anomalies (placeholder for future implementation).
    """
    # This would require IP geolocation data
    # For now, return empty list as placeholder
    return []


def send_anomaly_notifications(results):
    """
    Send notifications for critical anomalies.
    """
    critical_count = 0
    
    for result_type, flagged_ips in results.items():
        for suspicious_ip in flagged_ips:
            if suspicious_ip.severity == 'CRITICAL':
                critical_count += 1
    
    if critical_count > 0:
        logger.critical(f"ALERT: {critical_count} critical anomalies detected!")
        # Here you could send email, Slack notification, etc.


@shared_task
def cleanup_old_suspicious_ips():
    """
    Clean up old resolved suspicious IP entries.
    """
    try:
        # Delete resolved entries older than 30 days
        cutoff_date = timezone.now() - timedelta(days=30)
        deleted_count = SuspiciousIP.objects.filter(
            is_resolved=True,
            flagged_at__lt=cutoff_date
        ).delete()[0]
        
        logger.info(f"Cleaned up {deleted_count} old suspicious IP entries")
        return {'deleted_count': deleted_count}
        
    except Exception as exc:
        logger.error(f"Cleanup task failed: {str(exc)}")
        raise exc


@shared_task
def generate_anomaly_report():
    """
    Generate daily anomaly detection report.
    """
    try:
        # Get statistics for the last 24 hours
        last_24h = timezone.now() - timedelta(hours=24)
        
        stats = {
            'total_flagged': SuspiciousIP.objects.filter(flagged_at__gte=last_24h).count(),
            'critical_flags': SuspiciousIP.objects.filter(
                flagged_at__gte=last_24h,
                severity='CRITICAL'
            ).count(),
            'auto_blocked': SuspiciousIP.objects.filter(
                flagged_at__gte=last_24h,
                auto_blocked=True
            ).count(),
            'resolved_flags': SuspiciousIP.objects.filter(
                flagged_at__gte=last_24h,
                is_resolved=True
            ).count(),
        }
        
        logger.info(f"Daily anomaly report: {stats}")
        return stats
        
    except Exception as exc:
        logger.error(f"Report generation failed: {str(exc)}")
        raise exc
