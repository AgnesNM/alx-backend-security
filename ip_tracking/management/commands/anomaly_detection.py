from django.core.management.base import BaseCommand
from django.utils import timezone
from ip_tracking.tasks import detect_anomalies, generate_anomaly_report
from ip_tracking.models import SuspiciousIP


class Command(BaseCommand):
    help = 'Run anomaly detection manually or show statistics'

    def add_arguments(self, parser):
        parser.add_argument(
            '--run',
            action='store_true',
            help='Run anomaly detection immediately'
        )
        
        parser.add_argument(
            '--stats',
            action='store_true',
            help='Show anomaly detection statistics'
        )
        
        parser.add_argument(
            '--report',
            action='store_true',
            help='Generate anomaly report'
        )
        
        parser.add_argument(
            '--resolve',
            type=str,
            help='Mark suspicious IP as resolved'
        )
        
        parser.add_argument(
            '--list',
            action='store_true',
            help='List all suspicious IPs'
        )

    def handle(self, *args, **options):
        if options['run']:
            self.run_detection()
        elif options['stats']:
            self.show_stats()
        elif options['report']:
            self.generate_report()
        elif options['resolve']:
            self.resolve_ip(options['resolve'])
        elif options['list']:
            self.list_suspicious_ips()
        else:
            self.stdout.write(
                self.style.WARNING(
                    'Please specify an action: --run, --stats, --report, --resolve, or --list'
                )
            )

    def run_detection(self):
        """
