from django.contrib import admin
from .models import RequestLog, BlockedIP


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
    
    actions = ['block_selected_ips']
    
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
    
    def has_add_permission(self, request):
        return False  # Don't allow manual creation of request logs
