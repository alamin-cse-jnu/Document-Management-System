# dms/management/commands/setup_dms.py

from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from dms.models import UserProfile, Category, Team

class Command(BaseCommand):
    help = 'Sets up initial data for the Document Management System'

    def handle(self, *args, **kwargs):
        self.stdout.write('Creating initial categories...')
        categories = [
            'Broadcasting and Information Technology Wing Documents',
            'Legislative Support Wing Documents',
            'Administrative Support Wing Documents',
            'Human Resource Wing Documents',
            'Inter Parliamentary Affairs & Security Wing Documents',
            'Committee Support Wing Documents',
            'Finance & Public Relation Wing Documents',
            'Meeting Minutes',
            'Requirement Analysis',
            'Reports',
        ]
        
        for category_name in categories:
            Category.objects.get_or_create(name=category_name)
        
        self.stdout.write(self.style.SUCCESS('Successfully created categories'))
        
        # Check if admin exists
        try:
            admin = User.objects.get(username='alamin')
            self.stdout.write('Admin user already exists')
        except User.DoesNotExist:
            self.stdout.write('Creating admin user...')
            admin = User.objects.create_superuser(
                username='alamin',
                email='alamin@parliament.example',
                password='123'
            )
            # Make sure we set the admin role properly
            profile, created = UserProfile.objects.get_or_create(user=admin)
            profile.role = UserProfile.ROLE_ADMIN
            profile.save()
            self.stdout.write(self.style.SUCCESS('Successfully created admin user'))
        
        # Create default teams
        self.stdout.write('Creating default teams...')
        teams = [
            'Parliament Secretariat',
            'Technical Committee',
            'IT Team',
            'Consultant Team',
            'UNDP Team',
        ]
        
        for team_name in teams:
            team, created = Team.objects.get_or_create(name=team_name)
            team.members.add(admin)
            if created:
                self.stdout.write(f'Created team: {team_name}')
            else:
                self.stdout.write(f'Team {team_name} already exists')
        
        self.stdout.write(self.style.SUCCESS('Initial setup complete!'))