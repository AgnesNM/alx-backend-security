import ipaddress
from django.core.management.base import BaseCommand, CommandError
from ip_tracking.models import BlockedIP


class Command(BaseCommand):
    help = 'Block or unblock IP addresses'

    def add_arguments(self, parser):
        parser.add_argument(
            'ip_address',
            type=str,
            help='The IP address to block or unblock'
        )
        
        parser.add_argument(
            '--reason',
            type=str,
            default='',
            help='Reason for blocking the IP address'
        )
        
        parser.add_argument(
            '--unblock',
            action='store_true',
            help='Unblock the IP address instead of blocking it'
        )
        
        parser.add_argument(
            '--list',
            action='store_true',
            help='List all blocked IP addresses'
        )

    def handle(self, *args, **options):
        if options['list']:
            self.list_blocked_ips()
            return

        ip_address = options['ip_address']
        
        # Validate IP address format
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            raise CommandError(f'Invalid IP address format: {ip_address}')

        if options['unblock']:
            self.unblock_ip(ip_address)
        else:
            self.block_ip(ip_address, options['reason'])

    def block_ip(self, ip_address, reason):
        """
        Block an IP address.
        """
        try:
            blocked_ip = BlockedIP.block_ip(ip_address, reason)
            
            if blocked_ip:
                self.stdout.write(
                    self.style.SUCCESS(
                        f'Successfully blocked IP address: {ip_address}'
                    )
                )
                if reason:
                    self.stdout.write(f'Reason: {reason}')
            else:
                self.stdout.write(
                    self.style.WARNING(
                        f'IP address {ip_address} is already blocked'
                    )
                )
                
        except Exception as e:
            raise CommandError(f'Failed to block IP address: {str(e)}')

    def unblock_ip(self, ip_address):
        """
        Unblock an IP address.
        """
        try:
            success = BlockedIP.unblock_ip(ip_address)
            
            if success:
                self.stdout.write(
                    self.style.SUCCESS(
                        f'Successfully unblocked IP address: {ip_address}'
                    )
                )
            else:
                self.stdout.write(
                    self.style.WARNING(
                        f'IP address {ip_address} was not found in blocked list'
                    )
                )
                
        except Exception as e:
            raise CommandError(f'Failed to unblock IP address: {str(e)}')

    def list_blocked_ips(self):
        """
        List all blocked IP addresses.
        """
        blocked_ips = BlockedIP.objects.filter(is_active=True).order_by('-blocked_at')
        
        if not blocked_ips.exists():
            self.stdout.write(
                self.style.WARNING('No IP addresses are currently blocked')
            )
            return

        self.stdout.write(
            self.style.SUCCESS(f'Found {blocked_ips.count()} blocked IP addresses:')
        )
        
        self.stdout.write('-' * 80)
        self.stdout.write(f'{"IP Address":<15} {"Blocked At":<20} {"Reason":<30}')
        self.stdout.write('-' * 80)
        
        for blocked_ip in blocked_ips:
            self.stdout.write(
                f'{blocked_ip.ip_address:<15} '
                f'{blocked_ip.blocked_at.strftime("%Y-%m-%d %H:%M:%S"):<20} '
                f'{blocked_ip.reason or "No reason provided":<30}'
            )
