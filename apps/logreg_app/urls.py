from django.conf.urls import url, include
from . import views

urlpatterns = [
    url(r'^$', views.index),
    url(r'^process/(?P<typelogin>(login)|(register))$', views.process),
    url(r'^success$', views.success),
    url(r'^logout$', views.logout)
]