from django.conf.urls import url

from . import views

app_name = 'amc'
urlpatterns = [
    url(r'^$', views.index, name='index'),
    url(r'^publish$', views.publish, name='publish'),
]
