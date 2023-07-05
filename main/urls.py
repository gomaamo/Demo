from rest_framework_simplejwt.views import TokenRefreshView
from . import views
from django.urls import path


urlpatterns = [
    path('', views.api_root, name='main'),
    path('register/', views.RegistrationView.as_view(), name='register'),
    path('verify-email/', views.EmailVerificationView.as_view(), name='verify-email'),
    path('resend-verification-email/', views.ResendVerificationEmailView.as_view(), name='resend-verification-email'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('logout/', views.LogoutView.as_view(), name="logout"),
    path('request-password-reset-email/', views.RequestPasswordResetEmailView.as_view(),
         name='request-password-reset-email'),
    path('password-reset/<uidb64>/<token>/', views.PasswordResetTokenValidationView.as_view(),
         name='password-reset-confirm'),
    path('password-reset/', views.SetNewPasswordView.as_view(), name='password-reset'),
    path('users/', views.UserList.as_view(), name='user-list'),
    path('users/<int:pk>/', views.UserDetail.as_view(), name='user-detail'),
]
