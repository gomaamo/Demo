import jwt
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site
from django.http import HttpResponse
from django.urls import reverse
from django.utils.encoding import smart_bytes, smart_str, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework.decorators import api_view
from rest_framework_simplejwt.tokens import RefreshToken
from demo import settings
from .models import User
from .serializers import RegistrationSerializer, EmailVerificationSerializer, ResendVerificationEmailSerializer, \
    LoginSerializer, LogoutSerializer, RequestPasswordResetEmailSerializer, SetNewPasswordSerializer, UserSerializer
from rest_framework import generics, status, views, permissions
from rest_framework.response import Response
from .utils import Mail


@api_view(['GET', 'HEAD'])
def api_root(request, format=None):
    """
    Listing all the endpoints, except the endpoints that need arguments before being sent: verify-email,
    password-reset-confirm and user-detail
    """
    # replace http with https for production servers
    site_domain = f'http://{get_current_site(request).domain}'
    return Response({
        'register': site_domain + reverse('register'),
        'login': site_domain + reverse('login'),
        'refresh-token': site_domain + reverse('token_refresh'),
        'resend-verification-email': site_domain + reverse('resend-verification-email'),
        'request-password-reset-email': site_domain + reverse('request-password-reset-email'),
        'password-reset': site_domain + reverse('password-reset'),
        'user-list': site_domain + reverse('user-list'),
        'logout': site_domain + reverse('logout'),
    })


class RegistrationView(generics.GenericAPIView):
    serializer_class = RegistrationSerializer

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data

        # send verification email
        user = User.objects.get(email=user_data['email'])
        token = RefreshToken.for_user(user).access_token
        current_site_domain = get_current_site(request).domain
        relative_link = reverse('verify-email')

        verification_link = f'https://{current_site_domain}{relative_link}?token={token}'
        message = 'use the link below to verify your email.\n If you were not excepting any account verification ' \
                  'email, please ignore this \n'
        email_body = f'Hi {user.email},\n{message}{verification_link}'
        data = {
            'email_body': email_body,
            'to_email': user.email,
            'email_subject': 'Demo Email Verification'
        }
        Mail.send_email(data=data)
        return Response(user_data, status=status.HTTP_201_CREATED)


class EmailVerificationView(views.APIView):
    serializer_class = EmailVerificationSerializer

    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.is_active = True
                user.save()
            return Response({'Email Successfully Verified!'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as identifier:
            return Response({'error': 'Activation Expired!'}, status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as identifier:
            return Response({'error': 'Invalid Token!'}, status=status.HTTP_400_BAD_REQUEST)


class ResendVerificationEmailView(views.APIView):
    serializer_class = ResendVerificationEmailSerializer

    def post(self, request):
        email = request.data['email']
        try:
            if User.objects.filter(email=email).exists:
                user = User.objects.get(email__exact=email)
                token = RefreshToken.for_user(user).access_token
                current_site_domain = get_current_site(request).domain
                relative_link = reverse('verify-email')
                verification_link = f'https://{current_site_domain}{relative_link}?token={token}'
                message = 'use the link below to verify your email.\n If you were not excepting any account ' \
                          'verification email, please ignore this \n'
                email_body = f'Hi {user.email},\n{message}{verification_link}'
                data = {
                    'email_body': email_body,
                    'to_email': user.email,
                    'email_subject': 'Demo Email Verification'
                }
                Mail.send_email(data=data)
                return Response({'Verification Email sent. Please check your inbox!'}, status=status.HTTP_200_OK)
        except User.DoesNotExist as exc:
            return Response({'The email address does not match any user account!'}, status=status.HTTP_400_BAD_REQUEST)


class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class LogoutView(generics.GenericAPIView):
    serializer_class = LogoutSerializer
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({'success': True, 'message': 'Logged out successfully'}, status=status.HTTP_200_OK)


class RequestPasswordResetEmailView(generics.GenericAPIView):
    serializer_class = RequestPasswordResetEmailSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = request.data['email']
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)

            current_site = get_current_site(request=request).domain
            relative_link = reverse('password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})
            absurl = 'https://' + current_site + relative_link

            email_body = 'Hello! \n Use the link below to reset your password \n' + absurl
            data = {'email_body': email_body, 'to_email': user.email,
                    'email_subject': 'Reset your password'}
            Mail.send_email(data)

        return Response({'Success': 'Password reset email sent!'}, status=status.HTTP_200_OK)


class PasswordResetTokenValidationView(generics.GenericAPIView):
    def get(self, request, uidb64, token):
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'Error': 'Password reset link is expired! Please request for a new one!'},
                                status=status.HTTP_401_UNAUTHORIZED)

            return Response({'Success': True, 'Message': 'Valid Credentials', 'uidb64': uidb64, 'token': token},
                            status=status.HTTP_200_OK)
        except DjangoUnicodeDecodeError as exc:
            return Response({'Error': 'Token is not valid! Please request for a new one!'},
                            status=status.HTTP_401_UNAUTHORIZED)


class SetNewPasswordView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def put(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message': 'Password changed successfully!'}, status=status.HTTP_200_OK)


class UserList(generics.ListAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer


class UserDetail(generics.RetrieveAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
