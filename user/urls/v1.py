from django.urls import path, include
from rest_framework import routers
from user import views
router = routers.DefaultRouter()
router.register(r'profiles', views.UserViewSet)

profile_create = views.UserViewSet.as_view({
    'post': 'create'
})

urlpatterns = [
    path('', include(router.urls)),
    path('login', views.LoginWithEmail.as_view(), name='login'),
    path('change_password', views.ChangePassword.as_view(), name='change-password'),
    path('forgot_password', views.ForgotPassword.as_view(), name='forgot-password'),
    path('resend_otp', views.ForgotPassword.as_view(), name='forgot-password'),
    path('reset_password', views.ChangePasswordThroughOTPView.as_view(), name='forgot-password'),
    path('auth/google', views.GoogleSignInView.as_view(), name='auth-google'),
]