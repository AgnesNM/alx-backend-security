from django.contrib import admin
from django.utils.html import format_html
from .models import RequestLog, BlockedIP, SuspiciousIP


@admin.register(SuspiciousIP)
class SuspiciousIPAdmin(admin.ModelAdmin):
    list_display = [
        'ip_address', 
        'severity_badge', 
        'flagged_at', 
        'request_count', 
        'is_resolved',
        'auto_blocked'
    ]
    list_filter = [
        'severity', 
        'is_resolved', 
        'auto_blocked', 
        'flagged_at'
    ]
    search_fields = ['ip_address', 'reason']
    readonly_fields = ['flagged_at', 'auto_blocked']
    ordering = ['-flagged_at']
    
    actions = ['resolve_flags', 'block_suspicious_ips', 'mark_unresolved']
    
    def severity_badge(self, obj):
        colors = {
            'LOW': 'green',
            'MEDIUM': 'orange',
            'HIGH': 'red',
            'CRITICAL': 'darkred'
        }
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            colors.get(obj.severity, 'black'),
            obj.severity
        )
    severity_badge.short_description = 'Severity'
    
    def resolve_flags(self, request, queryset):
        """
        Mark selected suspicious IPs as resolved.
        """
        updated = queryset.update(is_resolved=True)
        self.message_user(
            request,
            f'{updated} suspicious IP flag(s) were marked as resolved.'
        )
    resolve_flags.short_description = "Mark selected flags as resolved"
    
    def block_suspicious_ips(self, request, queryset):
        """
        Block selected suspicious IPs.
        """
        blocked_count = 0
        for suspicious_ip in queryset:
            if not suspicious_ip.auto_blocked:
                BlockedIP.block_ip(
                    suspicious_ip.ip_address, 
                    reason=f"Blocked from admin: {suspicious_ip.reason}"
                )
                suspicious_ip.auto_blocked = True
                suspicious_ip.save()
                blocked_count += 1
        
        self.message_user(
            request,
            f'{blocked_count} suspicious IP(s) were successfully blocked.'
        )
    block_suspicious_ips.short_description = "Block selected suspicious IPs"
    
    def mark_unresolved(self, request, queryset):
        """
        Mark selected suspicious IPs as unresolved.
        """
        updated = queryset.update(is_resolved=False)
        self.message_user(
            request,
            f'{updated} suspicious IP flag(s) were marked as unresolved.'
        )
    mark_unresolved.short_description = "Mark selected flags as unresolved"


@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    list_display = ['ip_address', 'blocked_at', 'is_active', 'reason']
    list_filter = ['is_active', 'blocked_at']
    search_fields = ['ip_address', 'reason']
    readonly_fields = ['blocked_at']
    ordering = ['-blocked_at']
    
    actions = ['activate_block', 'deactivate_block']
    
    def activate_block(self, request, queryset):
        """
        Activate selected blocked IPs.
        """
        updated = queryset.update(is_active=True)
        self.message_user(
            request,
            f'{updated} IP block(s) were successfully activated.'
        )
    activate_block.short_description = "Activate selected IP blocks"
    
    def deactivate_block(self, request, queryset):
        """
        Deactivate selected blocked IPs.
        """
        updated = queryset.update(is_active=False)
        self.message_user(
            request,
            f'{updated} IP block(s) were successfully deactivated.'
        )
    deactivate_block.short_description = "Deactivate selected IP blocks"


@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    list_display = ['ip_address', 'path', 'timestamp']
    list_filter = ['timestamp']
    search_fields = ['ip_address', 'path']
    readonly_fields = ['ip_address', 'path', 'timestamp']
    ordering = ['-timestamp']
    
    actions = ['block_selected_ips', 'flag_suspicious_ips']
    
    def block_selected_ips(self, request, queryset):
        """
        Block IPs from selected request logs.
        """
        unique_ips = queryset.values_list('ip_address', flat=True).distinct()
        blocked_count = 0
        
        for ip in unique_ips:
            BlockedIP.block_ip(ip, reason="Blocked from admin panel")
            blocked_count += 1
        
        self.message_user(
            request,
            f'{blocked_count} unique IP address(es) were successfully blocked.'
        )
    block_selected_ips.short_description = "Block IPs from selected requests"
    
    def flag_suspicious_ips(self, request, queryset):
        """
        Flag IPs from selected request logs as suspicious.
        """
        unique_ips = queryset.values_list('ip_address', flat=True).distinct()
        flagged_count = 0
        
        for ip in unique_ips:
            SuspiciousIP.flag_ip(
                ip, 
                reason="Flagged from admin panel",
                severity='MEDIUM'
            )
            flagged_count += 1
        
        self.message_user(
            request,
            f'{flagged_count} unique IP address(es) were flagged as suspicious.'
        )
    flag_suspicious_ips.short_description = "Flag IPs from selected requests as suspicious"
    
    def has_add_permission(self, request):
        return False  # Don't allow manual creation of request logs
