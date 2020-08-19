from django.conf.urls import url
from django.urls import include
from django.contrib.staticfiles.urls import staticfiles_urlpatterns

urlpatterns = [
    url(r"", include("interface.urls"))
]

urlpatterns += staticfiles_urlpatterns()

