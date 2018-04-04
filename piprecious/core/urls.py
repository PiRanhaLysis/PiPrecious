from django.conf.urls import url

from . import views

app_name = 'core'
urlpatterns = [
    url(r'^$', views.index, name = 'index'),
    url(r'^apps$', views.application_list, name = 'application_list'),
    url(r'^smartphones$', views.smartphone_list, name = 'smartphone_list'),
    url(r'^devices$', views.device_list, name = 'device_list'),

    url(r'^api/smartphone$', views.api_smartphone, name = 'api_smartphone'),
    url(r'^api/smartphone/(?P<pk>[^/]+)/$', views.api_smartphone_get, name = 'api_smartphone_get'),
    url(r'^api/experiment/(?P<pk>[^/]+)/$', views.api_experiment_get, name = 'api_experiment_get'),
    url(r'^api/application/(?P<pk>[^/]+)/$', views.api_application_get, name = 'api_application_get'),
]