from django.conf.urls import url
from django.contrib import admin

from . import views

app_name = 'core'
urlpatterns = [
    url(r'^$', views.index, name = 'index'),
    url('^accounts/', admin.site.urls),
    url(r'^apps$', views.application_list, name = 'application_list'),
    url(r'^smartphones$', views.smartphone_list, name = 'smartphone_list'),
    url(r'^devices$', views.device_list, name = 'device_list'),
    url(r'^session/(?P<pk>[^/]+)/$', views.session_details, name = 'session_details'),
    url(r'^session/(?P<pk>[^/]+)/flow$', views.flow_details, name = 'flow_details'),
    url(r'^api/session/(?P<pk>[^/]+)/flow/details$', views.api_flow_details, name = 'api_flow_details'),

    url(r'^api/device', views.api_device_get, name = 'api_device_get'),

    url(r'^api/smartphone$', views.api_smartphone, name = 'api_smartphone'),
    url(r'^api/smartphone/(?P<pk>[^/]+)/$', views.api_smartphone_get, name = 'api_smartphone_get'),

    url(r'^experiment/(?P<pk>[^/]+)/report$', views.view_report, name = 'view_report'),
    url(r'^experiment/(?P<pk>[^/]+)/report/create$', views.create_report, name = 'create_report'),
    url(r'^experiments', views.experiment_list, name = 'experiment_list'),
    url(r'^api/experiment/(?P<pk>[^/]+)/$', views.api_experiment_get, name = 'api_experiment_get'),
    url(r'^api/experiment/(?P<pk>[^/]+)/session$', views.api_experiment_session, name = 'api_experiment_session'),

    url(r'^api/application/(?P<pk>[^/]+)/$', views.api_application_get, name = 'api_application_get'),
    url(r'^api/application/(?P<pk>[^/]+)/apk', views.api_apk_get, name = 'api_apk_get'),

    url(r'^api/session/(?P<pk>[^/]+)/flow/har', views.api_flow_har, name = 'api_flow_har'),
    url(r'^api/session/(?P<pk>[^/]+)/flow', views.api_flow, name = 'api_flow'),
    url(r'^api/session/(?P<pk>[^/]+)/pcap', views.api_pcap, name = 'api_pcap'),
    url(r'^api/session/(?P<pk>[^/]+)/bt', views.api_bt, name = 'api_bt'),
]