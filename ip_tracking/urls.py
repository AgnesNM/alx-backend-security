from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('password-reset/', views.password_reset_view, name='password_reset'),
    path('contact/', views.contact_view, name='contact'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('api/stats/', views.api_endpoint, name='api_stats'),
]
