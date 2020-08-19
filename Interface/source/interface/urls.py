from django.conf.urls import url
from django.urls import path
from django.urls import include
from . import views

app_name = 'interface'

urlpatterns = [
    url(r"^equipment/create$", views.create_equipment, name='Create a device'),
    url(r"^equipment/remove$", views.remove_equipment, name='Remove a device'),
    url(r"^equipment/list_service_on_device$", views.equipment_list_service_on_device, name='List all services on a device'),
    url(r"^service/enable", views.enable_service, name='Enable a device'),
    url(r"^service/suspend", views.suspend_service, name='Suspend a device'),
    url(r"^service/disable", views.disable_service, name='Disable a device'),
    url(r"^service/recommend_auth", views.recommend_auth, name='Reasons about authentication methods'),
    url(r"^policy/add", views.add_policy, name='Add a device'),
    url(r"^policy/remove", views.remove_policy, name='Remove a device'),
    url(r"^policy/bind_policy_to_individual", views.bind_policy_to_individual, name='Bind a policy to an individual'),
    url(r"^policy/remove_policy_of_individual", views.remove_policy_of_individual, name='Remove a policy bound to an individual'),
    url(r"^event/report_threat", views.report_threat, name='Report a threat to the engine'),
    url(r"^event/remove_threat", views.remove_threat,name='Remove a threat'),
    url(r"^context/add_context", views.add_context, name='Add a contextual individual'),
    url(r"^context/bind_context_to_individual", views.bind_context_to_individual, name='Bind a contextual individual to an individual'),
    url(r"^context/remove_context_of_individual", views.report_threat, name='Remove a contextual individual bound to an individual'),
    url(r"^user/add_user", views.add_user, name='Add a user')
]
