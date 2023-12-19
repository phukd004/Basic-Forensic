from django.urls import path
from .views import home, loading_screen, upload_failed, result, system, processes, network, other
from . import views

urlpatterns = [
    path('', home, name='home'),
    path('result/', result, name='result'),
    path('upload/', views.upload_file, name='upload_file'),
    path('success/', views.success, name='success'),
    path('loading-screen/', loading_screen, name='loading_screen'),
    path('upload-failed/', upload_failed, name='upload_failed'),
    path('system/', system, name='system'),
    path('processes/', processes, name='processes'),
    path('network/', network, name='network'),
    path('other/', other, name='other'),
]
