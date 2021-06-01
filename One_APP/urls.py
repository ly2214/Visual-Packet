from django.urls import path,re_path
from One_APP import views

urlpatterns = [
    path('', views.Index_View.as_view(), name = 'index'),
    path('table_View', views.Table_View.as_view(), name = 'table_View'),
    path('stop', views.Stop.as_view(), name = 'stop'),
    path('stevens', views.Seq_View.as_view(), name = 'stevens'),
    # path('chart_View', views.Charts_Seq.as_view(), name = 'chart_View'),
    path('console', views.Console.as_view(), name = 'console'),
    path('tcpflow', views.TCPFlow.as_view(), name = 'tcpflow'),
    path('tcpflow_View', views.TCPFlow_View.as_view(), name = 'tcpflow_View'),
    path('iograph', views.IOGraph.as_view(), name = 'iograph'),
    path('sankeyflow_View', views.SankeyFlow_View.as_view(), name = 'sankeyflow_View'),
    path('rtt', views.RTTGraph.as_view(), name = 'rtt'),
    # path('rtt_View', views.RTT_View.as_view(), name = 'rtt_View')
]