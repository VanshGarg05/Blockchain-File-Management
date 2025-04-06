from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    path('signup/', views.signup, name='signup'),
    path('', auth_views.LoginView.as_view(template_name='fileapp/login_page.html', redirect_authenticated_user=True), name='login'),
    path('logout/', views.logoff_view, name='logout'),
    path('home/', views.home, name='home'),
    path('upload/', views.upload_file, name='upload_file'),
    path('files/', views.file_list, name='file_list'),
    path('search/', views.search_file, name='search_file'),
    path('files/<int:file_id>/', views.file_detail, name='file_detail'),
    path('files/<int:file_id>/download/', views.download_file, name='download_file'),
]
