import logging
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse, HttpResponseForbidden
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods
from django_ratelimit.decorators import ratelimit
from django_ratelimit.exceptions import Ratelimited
from django.core.exceptions import PermissionDenied
from .models import RequestLog, BlockedIP


logger = logging.getLogger(__name__)


def ratelimit_handler(request, exception):
    """
    Custom handler for rate limit exceeded.
    """
    client_ip = get_client_ip(request)
    logger.warning(f"Rate limit exceeded for IP: {client_ip}")
    
    if request.headers.get('Content-Type') == 'application/json':
        return JsonResponse(
            {
                'error': 'Rate limit exceeded',
                'message': 'Too many requests. Please try again later.',
                'retry_after': 60
            },
            status=429
        )
    
    return render(request, 'rate_limited.html', {
        'message': 'Too many requests. Please try again later.',
        'retry_after': 60
    }, status=429)


def get_client_ip(request):
    """
    Get the real client IP address from the request.
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip or '0.0.0.0'


@csrf_protect
@require_http_methods(["GET", "POST"])
@ratelimit(key='ip', rate='5/m', method=['POST'], block=True)
@ratelimit(key='user', rate='10/m', method=['POST'], block=True)
def login_view(request):
    """
    Login view with rate limiting:
    - 5 requests/minute for anonymous users (by IP)
    - 10 requests/minute for authenticated users (by user)
    """
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        if not username or not password:
            messages.error(request, 'Please provide both username and password.')
            return render(request, 'login.html')
        
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            messages.success(request, f'Welcome back, {user.username}!')
            
            # Log successful login
            logger.info(f"Successful login for user: {username}, IP: {get_client_ip(request)}")
            
            # Redirect to next page or dashboard
            next_url = request.GET.get('next', '/dashboard/')
            return redirect(next_url)
        else:
            # Log failed login attempt
            client_ip = get_client_ip(request)
            logger.warning(f"Failed login attempt for username: {username}, IP: {client_ip}")
            
            messages.error(request, 'Invalid username or password.')
    
    return render(request, 'login.html')


@csrf_protect
@require_http_methods(["GET", "POST"])
@ratelimit(key='ip', rate='3/m', method=['POST'], block=True)
def password_reset_view(request):
    """
    Password reset view with strict rate limiting:
    - 3 requests/minute for all users (by IP)
    """
    if request.method == 'POST':
        email = request.POST.get('email')
        
        if not email:
            messages.error(request, 'Please provide an email address.')
            return render(request, 'password_reset.html')
        
        # Log password reset attempt
        client_ip = get_client_ip(request)
        logger.info(f"Password reset requested for email: {email}, IP: {client_ip}")
        
        # Here you would typically send password reset email
        # For now, just show success message
        messages.success(request, 'Password reset instructions sent to your email.')
        return redirect('login')
    
    return render(request, 'password_reset.html')


@csrf_protect
@require_http_methods(["GET", "POST"])
@ratelimit(key='ip', rate='20/m', method=['POST'], block=True)
@ratelimit(key='user', rate='30/m', method=['POST'], block=True)
def contact_view(request):
    """
    Contact form with moderate rate limiting:
    - 20 requests/minute for anonymous users (by IP)
    - 30 requests/minute for authenticated users (by user)
    """
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        message = request.POST.get('message')
        
        if not all([name, email, message]):
            messages.error(request, 'Please fill in all fields.')
            return render(request, 'contact.html')
        
        # Log contact form submission
        client_ip = get_client_ip(request)
        logger.info(f"Contact form submitted by: {email}, IP: {client_ip}")
        
        messages.success(request, 'Thank you for your message. We will get back to you soon.')
        return redirect('contact')
    
    return render(request, 'contact.html')


@require_http_methods(["GET"])
@ratelimit(key='ip', rate='100/m', method=['GET'], block=True)
def api_endpoint(request):
    """
    API endpoint with rate limiting:
    - 100 requests/minute (by IP)
    """
    # Get some stats
    total_requests = RequestLog.objects.count()
    blocked_ips = BlockedIP.objects.filter(is_active=True).count()
    
    return JsonResponse({
        'status': 'success',
        'data': {
            'total_requests': total_requests,
            'blocked_ips': blocked_ips,
            'client_ip': get_client_ip(request)
        }
    })


@login_required
@require_http_methods(["GET"])
def dashboard_view(request):
    """
    Dashboard view (no rate limiting for authenticated users accessing dashboard)
    """
    recent_logs = RequestLog.objects.all()[:10]
    blocked_ips = BlockedIP.objects.filter(is_active=True)[:5]
    
    return render(request, 'dashboard.html', {
        'recent_logs': recent_logs,
        'blocked_ips': blocked_ips,
        'user': request.user
    })


@require_http_methods(["POST"])
def logout_view(request):
    """
    Logout view (no rate limiting needed)
    """
    logout(request)
    messages.success(request, 'You have been logged out successfully.')
    return redirect('login')


# Custom view to handle rate limit exceptions
def handle_ratelimit_exception(request, exception):
    """
    Global handler for rate limit exceptions
    """
    return ratelimit_handler(request, exception)
