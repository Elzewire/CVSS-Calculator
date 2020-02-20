from django.urls import path

from calculator import views

urlpatterns = [
    path("", views.IndexView.as_view(), name="index"),
    path("cvss2/", views.Cvss2View.as_view(), name="cvss2"),
    path("cvss3/", views.Cvss3View.as_view(), name="cvss3"),
    path("cvss2/calc/", views.CVSS2_calc, name="cvss2_c"),
    path("cvss3/calc/", views.CVSS3_calc, name="cvss3_c")
]