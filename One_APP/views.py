import json
import os
import sys
from copy import deepcopy
from datetime import datetime
from os import listdir, path, remove
from re import sub
from socket import inet_ntoa
from threading import Event, Thread
from time import localtime, strftime
from itertools import groupby

import numpy as np
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render
from django.template import loader
from django.views.generic.base import TemplateView, View
from dpkt import ethernet, icmp, pcap, tcp, udp
from dpkt.compat import compat_ord
from dpkt.dpkt import hexdump
from rest_framework.views import APIView
from scapy.sendrecv import sniff
from scapy.utils import wrpcap

from .chart import CHART

global packet_data_list
packet_data_list = []               # 抓包分析到的原始数据

class MyEncoder(json.JSONEncoder):
    '''
    解决json.dumps无法序列化的问题
    '''
    def default(self, obj):
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, bytes):
            return str(obj, encoding='utf-8');
        return json.JSONEncoder.default(self, obj)


class Index_View(TemplateView): 
    template_name = "index.html"


# class Charts_Seq(APIView):
#     '''    
#     tcp stevens绘制
#     '''
#     def get(self, request, *args, **kwargs):
#         if packet_data_list:
#             CHART.packet_list = deepcopy(packet_data_list)
#             return JsonResponse(CHART.create('line_seq'))
#         else:
#             with open('data_json.json') as f:
#                 temp_data_list = json.load(f)
#             CHART.packet_list = deepcopy(temp_data_list)
#             return JsonResponse(CHART.create('line_seq'))

class Seq_View(APIView):
    def get(self, request, *args, **kwargs):
        if packet_data_list:
            CHART.packet_list = deepcopy(packet_data_list)
            template = loader.get_template('views/stevens.html')
            context = CHART.create('line_seq')
            return HttpResponse(template.render(context, request))
        else:
            with open('data_json.json') as f:
                temp_data_list = json.load(f)
            CHART.packet_list = deepcopy(temp_data_list)
            template = loader.get_template('views/stevens.html')
            context = CHART.create('line_seq')
            return HttpResponse(template.render(context, request))
    # def get(self, request, *args, **kwargs):
    #     return HttpResponse(content=open("templates/views/charts.html").read())


class TCPFlow_View(APIView):
    '''
    TCP的Flow绘制
    '''
    def get(self, request, *args, **kwargs):
        if packet_data_list:
            CHART.packet_list = deepcopy(packet_data_list)
            
            return JsonResponse(CHART.create('Graph_seq'))
        else:
            with open('data_json.json') as f:
                temp_data_list = json.load(f)
            CHART.packet_list = deepcopy(temp_data_list)
            return JsonResponse(CHART.create('line_seq'))

class TCPFlow(TemplateView):
    template_name = 'views/flow.html'


class SankeyFlow_View(APIView):
    '''
    IO Graphs绘制
    '''
    def get(self, request, *args, **kwargs):
        if packet_data_list:
            CHART.packet_list = deepcopy(packet_data_list)
            return JsonResponse(CHART.create('Sankey_IO'))
        else:
            with open('data_json.json') as f:
                temp_data_list = json.load(f)
            CHART.packet_list = deepcopy(temp_data_list)
            return JsonResponse(CHART.create('Sankey_IO'))

class IOGraph(TemplateView):
    template_name = 'views/sankey.html'


# class RTT_View(APIView):
#     '''
#     HTTPResponse直接读取html
#     调用url：tcpflow_View
#     '''
#     def get(self, request, *args, **kwargs):
#         if packet_data_list:
#             CHART.packet_list = deepcopy(packet_data_list)
#             return JsonResponse(CHART.create('Scatter_RTT'))
#         else:
#             with open('data_json.json') as f:
#                 temp_data_list = json.load(f)
#             CHART.packet_list = deepcopy(temp_data_list)
#             return JsonResponse(CHART.create('Scatter_RTT'))

class RTTGraph(APIView):
    def get(self, request, *args, **kwargs):
        if packet_data_list:
            CHART.packet_list = deepcopy(packet_data_list)
            template = loader.get_template('views/rtt.html')
            context = CHART.create('Scatter_RTT')
            return HttpResponse(template.render(context, request))
        else:
            with open('data_json.json') as f:
                temp_data_list = json.load(f)
            CHART.packet_list = deepcopy(temp_data_list)
            template = loader.get_template('views/rtt.html')
            context = CHART.create('Scatter_RTT')
            return HttpResponse(template.render(context, request))


class Console(TemplateView):
    template_name = "views/console.html"



# 字典存储syn报文的内容，同时用于求相对序列号
syn_packet_context = {}
# 存储所有syn报文，用于求相对序列号
syn_packet = []

tcp_or_udp = {}
tcp_or_udp[6] = 'tcp'
tcp_or_udp[17] = 'udp'
tcp_or_udp[1] = 'icmp'
tcp_or_udp[2] = 'igmp'
tcp_or_udp[89] = 'ospf'

pack_num = 0
thread_flag = True             # 线程是否已创建标志位


def mac_addr(address):
    """
    将Mac地址转换为可读字符串
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)


class Parse():
    def __init__(self, parent=None):
        """
        初始化抓包列表，抓包线程事件对象
        """
        self.first_time = float()           # 第一个包的时间需要设置为全局变量
        self.packet_list = []
        self.added_rela_list = []           # 计算过相对序列号后的解析数据集
        self.fil = ''
        self.stop_sending = Event()
        
    def del_file(self):
        """
        删除文件夹下面的所有文件
        """
        relative_path = r'packet'
        for i in listdir(relative_path):          # os.listdir()返回一个列表，里面是当前目录下面的所有文件和文件夹的相对路径
            file_path = path.join(relative_path, i)
            if path.isfile(file_path) == True:    # os.path.isfile判断是否为文件,如果是文件,就删除.如果是文件夹.递归给del_file.(该段代码特殊就省略了)  
                remove(file_path)

    # def get_pack(self):
    #     if self.packet_list:
    #         pack = self.packet_list.pop(-1)  # PS：index = -1，删除最后一个列表值
    #         return pack
    #     else:
    #         return
        
    def run(self):
        """
        嗅探开启
        """
        # 设置抓包事件开启
        self.stop_sending.clear()
        '''
        抓取数据包并调用处理抓包函数process_packet
        '''
        sniff(prn=lambda x: self.parse_packet(x), filter="tcp", stop_filter=(lambda x:self.stop_sending.is_set()))

    def parse_packet(self, packet):
        """
        包解析
        """
        # 存储包到本地文件
        global pack_num
        pack_num = pack_num + 1
        file = 'packet\pack' + str(pack_num)
        filename = file + '.pcap'
        wrpcap(filename, packet)

        self.parse(filename)
        self.parse_packetlist(self.packet_list)

        # with open('test.txt', "w") as f:  
        #     f.write(str(self.added_rela_list))

        jsonArr = json.dumps(self.added_rela_list, ensure_ascii=False) 
        f2 = open('test_json.json', 'w')
        f2.write(jsonArr)
        f2.close()
        global packet_data_list
        packet_data_list = deepcopy(self.added_rela_list)


    def parse_packetlist(self, pack_lis):
        '''
        将抓取到的包按源地址和目的地址分割并进行相对序列号和确认号  的计算
        '''
        # 参数key中设置排序和分组标准为源IP地址和目的IP地址
        sorted_packet_list = sorted(pack_lis, key=lambda x: (x["Source"], x["Destination"], x["Source Port"], x["Destination Port"]))
        grouped_packet_list = groupby(sorted_packet_list, key=lambda x: (x["Source"], x["Destination"], x["Source Port"], x["Destination Port"]))
        group_list = []             # 将多个分割的列表装入一个列表集中
        for key, group in grouped_packet_list:
            group = list(group)
            group = sorted(group, key=lambda x: x["Ptime"])
            group_list.append(group)
    
        real_lis = []
        for lis in group_list:
            flags = False              #tcp是否建立起连接的标志(第三次握手)，用于判断是建立起第二次syn连接还是第一次的syn
            if lis[0]['flags'] == '0x002':
                # syn_packet_context为某个传输线路的基准数据包，pack为该传输线路中遍历得到的某个数据包，二者之差（或者加一）获得相对序列号和相对确认号
                syn_packet_context = {}
                syn_packet_context["Sequence"] = lis[0]["Sequence Number"]
                syn_packet_context["Ack"] = 0
                syn_packet_context["Source"] = lis[0]["Source"]
                syn_packet_context["Destination"] = lis[0]["Destination"]
                syn_packet_context["Source Port"] = lis[0]["Source Port"]
                syn_packet_context["Destination Port"] = lis[0]["Destination Port"]

                for i, pack in zip(range(len(lis)), lis):
                    if pack['flags'] == '0x002':
                        # syn报文连续发送的情况
                        if flags == False and syn_packet_context["Source Port"] == pack["Source Port"] and syn_packet_context["Destination Port"] == pack["Destination Port"]:
                            lis[i]["Flags"] = '0x002' + "[SYN]"
                            lis[i]["Relative Sequence Number"] = 0
                            lis[i]["Relative ACK Number"] = 0
                            lis[i]["Info"] = "[SYN]" + " seq=" + str(lis[i]["Relative Sequence Number"]) + " ack=" + str(lis[i]["Relative ACK Number"]) + " win=" + str(lis[i]['window']) + " len=" + str(lis[i]['Data Length'])
                        # 第n次建立syn连接，重新刷新syn计算
                        else:
                            syn_packet_context = {}
                            syn_packet_context["Sequence"] = pack["Sequence Number"]
                            syn_packet_context["Ack"] = 0
                            syn_packet_context["Source"] = pack["Source"]
                            syn_packet_context["Destination"] = pack["Destination"]
                            syn_packet_context["Source Port"] = pack["Source Port"]
                            syn_packet_context["Destination Port"] = pack["Destination Port"]
                            lis[i]["Flags"] = '0x002' + "[SYN]"
                            lis[i]["Relative Sequence Number"] = 0
                            lis[i]["Relative ACK Number"] = 0
                            lis[i]["Info"] = "[SYN]" + " seq=" + str(lis[i]["Relative Sequence Number"]) + " ack=" + str(lis[i]["Relative ACK Number"]) + " win=" + str(lis[i]['window']) + " len=" + str(lis[i]['Data Length'])
                            flags = False

                    elif pack['flags'] == '0x010':
                        lis[i]["Flags"] = '0x010' + "[ACK]"
                        lis[i]["Relative Sequence Number"] = pack["Sequence Number"] - syn_packet_context["Sequence"]
                        lis[i]["Relative ACK Number"] = pack["Acknowledge Number"] - syn_packet_context["Ack"] + 1
                        # 最后一次握手的数据包，以此为相对ack的计算，第一次连接成功
                        if lis[i]["Relative Sequence Number"] == 1:
                            lis[i]["Relative ACK Number"] = 1
                            syn_packet_context["Ack"] = pack["Acknowledge Number"]
                            flags == True
                        lis[i]["Info"] = "[ACK]" + " seq=" + str(lis[i]["Relative Sequence Number"]) + " ack=" + str(lis[i]["Relative ACK Number"]) + " win=" + str(lis[i]['window']) + " len=" + str(lis[i]['Data Length'])
                    
                    elif pack['flags'] == '0x019':
                        lis[i]["Flags"] = '0x019' + "[FIN][PSH][ACK]"
                        lis[i]["Relative Sequence Number"] = pack["Sequence Number"] - syn_packet_context["Sequence"]
                        lis[i]["Relative ACK Number"] = pack["Acknowledge Number"] - syn_packet_context["Ack"] + 1
                        lis[i]["Info"] = "[FIN][PSH][ACK]" + " seq=" + str(lis[i]["Relative Sequence Number"]) + " ack=" + str(lis[i]["Relative ACK Number"]) + " win=" + str(lis[i]['window']) + " len=" + str(lis[i]['Data Length'])

                    elif pack['flags'] == '0x011':
                        lis[i]["Flags"] = '0x011' + "[FIN][ACK]"
                        lis[i]["Relative Sequence Number"] = pack["Sequence Number"] - syn_packet_context["Sequence"]
                        lis[i]["Relative ACK Number"] = pack["Acknowledge Number"] - syn_packet_context["Ack"] + 1
                        lis[i]["Info"] = "[FIN][ACK]" + " seq=" + str(lis[i]["Relative Sequence Number"]) + " ack=" + str(lis[i]["Relative ACK Number"]) + " win=" + str(lis[i]['window']) + " len=" + str(lis[i]['Data Length'])

                    elif pack['flags'] == '0x018':
                        lis[i]["Flags"] = '0x018' + "[PSH][ACK]"
                        lis[i]["Relative Sequence Number"] = pack["Sequence Number"] - syn_packet_context["Sequence"]
                        lis[i]["Relative ACK Number"] = pack["Acknowledge Number"] - syn_packet_context["Ack"] + 1
                        lis[i]["Info"] = "[PSH][ACK]" + " seq=" + str(lis[i]["Relative Sequence Number"]) + " ack=" + str(lis[i]["Relative ACK Number"]) + " win=" + str(lis[i]['window']) + " len=" + str(lis[i]['Data Length'])

                    elif pack['flags'] == '0x014':
                        lis[i]["Flags"] = '0x014' + "[RST][ACK]"
                        lis[i]["Relative Sequence Number"] = pack["Sequence Number"] - syn_packet_context["Sequence"]
                        lis[i]["Relative ACK Number"] = pack["Acknowledge Number"] - syn_packet_context["Ack"] + 1
                        lis[i]["Info"] = "[RST][ACK]" + " seq=" + str(lis[i]["Relative Sequence Number"]) + " ack=" + str(lis[i]["Relative ACK Number"]) + " win=" + str(lis[i]['window']) + " len=" + str(lis[i]['Data Length'])
                    
                    elif pack['flags'] == '0x004':
                        lis[i]["Flags"] = "[RST]"
                        lis[i]["Relative Sequence Number"] = pack["Sequence Number"] - syn_packet_context["Sequence"]
                        lis[i]["Relative ACK Number"] = None
                        lis[i]["Info"] = "[RST]" + " seq=" + str(lis[i]["Relative Sequence Number"]) + " ack=" + str(lis[i]["Relative ACK Number"]) + " win=" + str(lis[i]['window']) + " len=" + str(lis[i]['Data Length'])
                    else:
                        print("----------------------------------------------------------")
                        print("TCP is not regular!!!")

                real_lis += lis      

            elif lis[0]['flags'] == '0x012':
                syn_packet_context = {}
                syn_packet_context["Sequence"] = lis[0]["Sequence Number"]
                syn_packet_context["Ack"] = lis[0]["Acknowledge Number"]
                syn_packet_context["Source"] = lis[0]["Source"]
                syn_packet_context["Destination"] = lis[0]["Destination"]
                syn_packet_context["Source Port"] = lis[0]["Source Port"]
                syn_packet_context["Destination Port"] = lis[0]["Destination Port"]

                for i, pack in zip(range(len(lis)), lis):
                    if pack['flags'] == '0x012':
                        if syn_packet_context["Source Port"] == pack["Source Port"] and syn_packet_context["Destination Port"] == pack["Destination Port"]:
                            lis[i]["Flags"] = '0x012' + '[SYN][ACK]'
                            lis[i]["Relative Sequence Number"] = 0
                            lis[i]["Relative ACK Number"] = 1
                            lis[i]["Info"] = '[SYN][ACK]' + " seq=" + str(lis[i]["Relative Sequence Number"]) + " ack=" + str(lis[i]["Relative ACK Number"]) + " win=" + str(lis[i]['window']) + " len=" + str(lis[i]['Data Length'])
                        else:
                            syn_packet_context = {}
                            syn_packet_context["Sequence"] = pack["Sequence Number"]
                            syn_packet_context["Ack"] = 0
                            syn_packet_context["Source"] = pack["Source"]
                            syn_packet_context["Destination"] = pack["Destination"]
                            syn_packet_context["Source Port"] = pack["Source Port"]
                            syn_packet_context["Destination Port"] = pack["Destination Port"]
                            lis[i]["Flags"] = '0x012' + '[SYN][ACK]'
                            lis[i]["Relative Sequence Number"] = 0
                            lis[i]["Relative ACK Number"] = 1
                            lis[i]["Info"] = '[SYN][ACK]' + " seq=" + str(lis[i]["Relative Sequence Number"]) + " ack=" + str(lis[i]["Relative ACK Number"]) + " win=" + str(lis[i]['window']) + " len=" + str(lis[i]['Data Length'])

                    elif pack['flags'] == '0x010':
                        lis[i]["Flags"] = '0x010' + "[ACK]"
                        lis[i]["Relative Sequence Number"] = pack["Sequence Number"] - syn_packet_context["Sequence"]
                        lis[i]["Relative ACK Number"] = pack["Acknowledge Number"] - syn_packet_context["Ack"] + 1
                        lis[i]["Info"] = "[ACK]" + " seq=" + str(lis[i]["Relative Sequence Number"]) + " ack=" + str(lis[i]["Relative ACK Number"]) + " win=" + str(lis[i]['window']) + " len=" + str(lis[i]['Data Length'])
                    
                    elif pack['flags'] == '0x019':
                        lis[i]["Flags"] = '0x019' + "[FIN][PSH][ACK]"
                        lis[i]["Relative Sequence Number"] = pack["Sequence Number"] - syn_packet_context["Sequence"]
                        lis[i]["Relative ACK Number"] = pack["Acknowledge Number"] - syn_packet_context["Ack"] + 1
                        lis[i]["Info"] = "[FIN][PSH][ACK]" + " seq=" + str(lis[i]["Relative Sequence Number"]) + " ack=" + str(lis[i]["Relative ACK Number"]) + " win=" + str(lis[i]['window']) + " len=" + str(lis[i]['Data Length'])

                    elif pack['flags'] == '0x011':
                        lis[i]["Flags"] = '0x011' + "[FIN][ACK]"
                        lis[i]["Relative Sequence Number"] = pack["Sequence Number"] - syn_packet_context["Sequence"]
                        lis[i]["Relative ACK Number"] = pack["Acknowledge Number"] - syn_packet_context["Ack"] + 1
                        lis[i]["Info"] = "[FIN][ACK]" + " seq=" + str(lis[i]["Relative Sequence Number"]) + " ack=" + str(lis[i]["Relative ACK Number"]) + " win=" + str(lis[i]['window']) + " len=" + str(lis[i]['Data Length'])

                    elif pack['flags'] == '0x018':
                        lis[i]["Flags"] = '0x018' + "[PSH][ACK]"
                        lis[i]["Relative Sequence Number"] = pack["Sequence Number"] - syn_packet_context["Sequence"]
                        lis[i]["Relative ACK Number"] = pack["Acknowledge Number"] - syn_packet_context["Ack"] + 1
                        lis[i]["Info"] = "[PSH][ACK]" + " seq=" + str(lis[i]["Relative Sequence Number"]) + " ack=" + str(lis[i]["Relative ACK Number"]) + " win=" + str(lis[i]['window']) + " len=" + str(lis[i]['Data Length'])

                    elif pack['flags'] == '0x014':
                        lis[i]["Flags"] = '0x014' + "[RST][ACK]"
                        lis[i]["Relative Sequence Number"] = pack["Sequence Number"] - syn_packet_context["Sequence"]
                        lis[i]["Relative ACK Number"] = pack["Acknowledge Number"] - syn_packet_context["Ack"] + 1
                        lis[i]["Info"] = "[RST][ACK]" + " seq=" + str(lis[i]["Relative Sequence Number"]) + " ack=" + str(lis[i]["Relative ACK Number"]) + " win=" + str(lis[i]['window']) + " len=" + str(lis[i]['Data Length'])
                    
                    elif pack['flags'] == '0x004':
                        lis[i]["Flags"] = "[RST]"
                        lis[i]["Relative Sequence Number"] = pack["Sequence Number"] - syn_packet_context["Sequence"]
                        lis[i]["Relative ACK Number"] = None
                        lis[i]["Info"] = "[RST]" + " seq=" + str(lis[i]["Relative Sequence Number"]) + " ack=" + str(lis[i]["Relative ACK Number"]) + " win=" + str(lis[i]['window']) + " len=" + str(lis[i]['Data Length'])
                    else:
                        print("----------------------------------------------------------")
                        print("TCP is not regular!!!")
               
                real_lis += lis

            else:
                lis[0]["Relative Sequence Number"] = 1
                lis[0]["Relative ACK Number"] = 1
                syn_packet_context = {}
                syn_packet_context["Sequence"] = lis[0]["Sequence Number"]
                syn_packet_context["Ack"] = lis[0]["Acknowledge Number"]
                syn_packet_context["Source"] = lis[0]["Source"]
                syn_packet_context["Destination"] = lis[0]["Destination"]
                syn_packet_context["Source Port"] = lis[0]["Source Port"]
                syn_packet_context["Destination Port"] = lis[0]["Destination Port"]
                syn_packet_context_copy = {}
                syn_packet_context_copy = deepcopy(syn_packet_context)
                syn_packet.append(syn_packet_context_copy)

                for i, pack in zip(range(len(lis)), lis):
                    # 不考虑可能重新建立SYN连接的可能性
                    if pack['flags'] == '0x010':
                        if syn_packet_context["Source Port"] == pack["Source Port"] and syn_packet_context["Destination Port"] == pack["Destination Port"]:
                            if i == 0:
                                lis[i]["Info"] = "[ACK]" + " seq=" + str(lis[i]["Relative Sequence Number"]) + " ack=" + str(lis[i]["Relative ACK Number"]) + " win=" + str(lis[i]['window']) + " len=" + str(lis[i]['Data Length'])
                                lis[i]["Flags"] = '0x010' + "[ACK]"
                            else:
                                lis[i]["Flags"] = '0x019' + "[FIN][PSH][ACK]"
                                lis[i]["Relative Sequence Number"] = pack["Sequence Number"] - syn_packet_context["Sequence"] + 1
                                lis[i]["Relative ACK Number"] = pack["Acknowledge Number"] - syn_packet_context["Ack"] + 1
                                lis[i]["Info"] = "[FIN][PSH][ACK]" + " seq=" + str(lis[i]["Relative Sequence Number"]) + " ack=" + str(lis[i]["Relative ACK Number"]) + " win=" + str(lis[i]['window']) + " len=" + str(lis[i]['Data Length'])
                        else:
                            lis[i]["Flags"] = '0x010' + "[ACK]"
                            lis[i]["Relative Sequence Number"] = 1
                            lis[i]["Relative ACK Number"] = 1
                            lis[i]["Info"] = "[ACK]" + " seq=" + str(lis[i]["Relative Sequence Number"]) + " ack=" + str(lis[i]["Relative ACK Number"]) + " win=" + str(lis[i]['window']) + " len=" + str(lis[i]['Data Length'])
                            syn_packet_context = {}
                            syn_packet_context["Sequence"] = pack["Sequence Number"]
                            syn_packet_context["Ack"] = pack["Acknowledge Number"]
                            syn_packet_context["Source"] = pack["Source"]
                            syn_packet_context["Destination"] = pack["Destination"]
                            syn_packet_context["Source Port"] = pack["Source Port"]
                            syn_packet_context["Destination Port"] = pack["Destination Port"]

                    elif pack['flags'] == '0x019':
                        if syn_packet_context["Source Port"] == pack["Source Port"] and syn_packet_context["Destination Port"] == pack["Destination Port"]:
                            lis[i]["Flags"] = '0x019' + "[FIN][PSH][ACK]"
                            lis[i]["Relative Sequence Number"] = pack["Sequence Number"] - syn_packet_context["Sequence"] + 1
                            lis[i]["Relative ACK Number"] = pack["Acknowledge Number"] - syn_packet_context["Ack"] + 1
                            lis[i]["Info"] = "[FIN][PSH][ACK]" + " seq=" + str(lis[i]["Relative Sequence Number"]) + " ack=" + str(lis[i]["Relative ACK Number"]) + " win=" + str(lis[i]['window']) + " len=" + str(lis[i]['Data Length'])
                        else:
                            lis[i]["Flags"] = '0x019' + "[FIN][PSH][ACK]"
                            lis[i]["Relative Sequence Number"] = 1
                            lis[i]["Relative ACK Number"] = 1
                            lis[i]["Info"] = "[FIN][PSH][ACK]" + " seq=" + str(lis[i]["Relative Sequence Number"]) + " ack=" + str(lis[i]["Relative ACK Number"]) + " win=" + str(lis[i]['window']) + " len=" + str(lis[i]['Data Length'])
                            syn_packet_context = {}
                            syn_packet_context["Sequence"] = pack["Sequence Number"]
                            syn_packet_context["Ack"] = pack["Acknowledge Number"]
                            syn_packet_context["Source"] = pack["Source"]
                            syn_packet_context["Destination"] = pack["Destination"]
                            syn_packet_context["Source Port"] = pack["Source Port"]
                            syn_packet_context["Destination Port"] = pack["Destination Port"]


                    elif pack['flags'] == '0x011':
                        if syn_packet_context["Source Port"] == pack["Source Port"] and syn_packet_context["Destination Port"] == pack["Destination Port"]:
                            if i == 0:
                                lis[i]["Info"] = "[FIN][ACK]" + " seq=" + str(lis[i]["Relative Sequence Number"]) + " ack=" + str(lis[i]["Relative ACK Number"]) + " win=" + str(lis[i]['window']) + " len=" + str(lis[i]['Data Length'])
                                lis[i]["Flags"] = '0x011' + "[FIN][ACK]"
                            else:
                                lis[i]["Flags"] = '0x011' + "[FIN][ACK]"
                                lis[i]["Relative Sequence Number"] = pack["Sequence Number"] - syn_packet_context["Sequence"] + 1
                                lis[i]["Relative ACK Number"] = pack["Acknowledge Number"] - syn_packet_context["Ack"] + 1
                                lis[i]["Info"] = "[FIN][ACK]" + " seq=" + str(lis[i]["Relative Sequence Number"]) + " ack=" + str(lis[i]["Relative ACK Number"]) + " win=" + str(lis[i]['window']) + " len=" + str(lis[i]['Data Length'])
                        else:
                            lis[i]["Flags"] = '0x011' + "[FIN][ACK]"
                            lis[i]["Relative Sequence Number"] = 1
                            lis[i]["Relative ACK Number"] = 1
                            lis[i]["Info"] = "[FIN][ACK]" + " seq=" + str(lis[i]["Relative Sequence Number"]) + " ack=" + str(lis[i]["Relative ACK Number"]) + " win=" + str(lis[i]['window']) + " len=" + str(lis[i]['Data Length'])
                            syn_packet_context = {}
                            syn_packet_context["Sequence"] = pack["Sequence Number"]
                            syn_packet_context["Ack"] = pack["Acknowledge Number"]
                            syn_packet_context["Source"] = pack["Source"]
                            syn_packet_context["Destination"] = pack["Destination"]
                            syn_packet_context["Source Port"] = pack["Source Port"]
                            syn_packet_context["Destination Port"] = pack["Destination Port"]

                    elif pack['flags'] == '0x018':
                        if syn_packet_context["Source Port"] == pack["Source Port"] and syn_packet_context["Destination Port"] == pack["Destination Port"]:
                            if i==0:
                                lis[i]["Flags"] = '0x018' + "[PSH][ACK]"
                                lis[i]["Info"] = "[PSH][ACK]" + " seq=" + str(lis[i]["Relative Sequence Number"]) + " ack=" + str(lis[i]["Relative ACK Number"]) + " win=" + str(lis[i]['window']) + " len=" + str(lis[i]['Data Length'])
                            else:
                                lis[i]["Flags"] = '0x018' + "[PSH][ACK]"
                                lis[i]["Relative Sequence Number"] = pack["Sequence Number"] - syn_packet_context["Sequence"] + 1
                                lis[i]["Relative ACK Number"] = pack["Acknowledge Number"] - syn_packet_context["Ack"] + 1
                                lis[i]["Info"] = "[PSH][ACK]" + " seq=" + str(lis[i]["Relative Sequence Number"]) + " ack=" + str(lis[i]["Relative ACK Number"]) + " win=" + str(lis[i]['window']) + " len=" + str(lis[i]['Data Length'])
                        else:
                            lis[i]["Flags"] = '0x018' + "[PSH][ACK]"
                            lis[i]["Relative Sequence Number"] = 1
                            lis[i]["Relative ACK Number"] = 1
                            lis[i]["Info"] = "[PSH][ACK]" + " seq=" + str(lis[i]["Relative Sequence Number"]) + " ack=" + str(lis[i]["Relative ACK Number"]) + " win=" + str(lis[i]['window']) + " len=" + str(lis[i]['Data Length'])
                            syn_packet_context = {}
                            syn_packet_context["Sequence"] = pack["Sequence Number"]
                            syn_packet_context["Ack"] = pack["Acknowledge Number"]
                            syn_packet_context["Source"] = pack["Source"]
                            syn_packet_context["Destination"] = pack["Destination"]
                            syn_packet_context["Source Port"] = pack["Source Port"]
                            syn_packet_context["Destination Port"] = pack["Destination Port"]

                    elif pack['flags'] == '0x014':
                        if syn_packet_context["Source Port"] == pack["Source Port"] and syn_packet_context["Destination Port"] == pack["Destination Port"]:
                            if i==0:
                                lis[i]["Flags"] = '0x014' + "[RST][ACK]"
                                lis[i]["Info"] = "[RST][ACK]" + " seq=" + str(lis[i]["Relative Sequence Number"]) + " ack=" + str(lis[i]["Relative ACK Number"]) + " win=" + str(lis[i]['window']) + " len=" + str(lis[i]['Data Length'])
                            else:
                                lis[i]["Flags"] = '0x014' + "[RST][ACK]"
                                lis[i]["Relative Sequence Number"] = pack["Sequence Number"] - syn_packet_context["Sequence"] + 1
                                lis[i]["Relative ACK Number"] = pack["Acknowledge Number"] - syn_packet_context["Ack"] + 1
                                lis[i]["Info"] = "[RST][ACK]" + " seq=" + str(lis[i]["Relative Sequence Number"]) + " ack=" + str(lis[i]["Relative ACK Number"]) + " win=" + str(lis[i]['window']) + " len=" + str(lis[i]['Data Length'])
                        else:
                            lis[i]["Flags"] = '0x014' + "[RST][ACK]"
                            lis[i]["Relative Sequence Number"] = 1
                            lis[i]["Relative ACK Number"] = 1
                            lis[i]["Info"] = "[RST][ACK]" + " seq=" + str(lis[i]["Relative Sequence Number"]) + " ack=" + str(lis[i]["Relative ACK Number"]) + " win=" + str(lis[i]['window']) + " len=" + str(lis[i]['Data Length'])
                            syn_packet_context = {}
                            syn_packet_context["Sequence"] = pack["Sequence Number"]
                            syn_packet_context["Ack"] = pack["Acknowledge Number"]
                            syn_packet_context["Source"] = pack["Source"]
                            syn_packet_context["Destination"] = pack["Destination"]
                            syn_packet_context["Source Port"] = pack["Source Port"]
                            syn_packet_context["Destination Port"] = pack["Destination Port"]
                    
                    elif pack['flags'] == '0x004':
                        if syn_packet_context["Source Port"] == pack["Source Port"] and syn_packet_context["Destination Port"] == pack["Destination Port"]:
                            lis[i]["Flags"] = "[RST]"
                            lis[i]["Relative Sequence Number"] = pack["Sequence Number"] - syn_packet_context["Sequence"] + 1
                            lis[i]["Relative ACK Number"] = None
                            lis[i]["Info"] = "[RST]" + " seq=" + str(lis[i]["Relative Sequence Number"]) + " ack=" + str(lis[i]["Relative ACK Number"]) + " win=" + str(lis[i]['window']) + " len=" + str(lis[i]['Data Length'])
                        else:
                            lis[i]["Flags"] = "[RST]"
                            lis[i]["Relative Sequence Number"] = 1
                            lis[i]["Relative ACK Number"] = None
                            lis[i]["Info"] = "[RST]" + " seq=" + str(lis[i]["Relative Sequence Number"]) + " ack=" + str(lis[i]["Relative ACK Number"]) + " win=" + str(lis[i]['window']) + " len=" + str(lis[i]['Data Length'])
                            syn_packet_context = {}
                            syn_packet_context["Sequence"] = pack["Sequence Number"]
                            syn_packet_context["Ack"] = pack["Acknowledge Number"]
                            syn_packet_context["Source"] = pack["Source"]
                            syn_packet_context["Destination"] = pack["Destination"]
                            syn_packet_context["Source Port"] = pack["Source Port"]
                            syn_packet_context["Destination Port"] = pack["Destination Port"]
                    else:
                        print("----------------------------------------------------------")
                        print("TCP is not regular!!!")             
                real_lis += lis

        self.added_rela_list = sorted(real_lis, key=lambda x: x["Ptime"])
    #     """
    #     批量读取静态数据包解析
    #     """
    #     packet_files = []
    #     # files = os.listdir(os.path.dirname(os.path.abspath(__file__)))
    #     files = os.listdir("./packet")
    #     for file in files:
    #         if os.path.splitext(file)[1] == '.pcap':             # 文件名和扩展名能直接分开
    #             packet_files.append(file)

    #     for file in packet_files:
    #         filename = "./packet/" + file
    #         self.parse(filename)

    #     global packet_data_list
    #     packet_data_list = deepcopy(self.packet_list)
    #     return self.packet_list


    def parse(self, filename):
        '''
        解析pcap文件包头packet_data
        '''
        fl = open(filename, 'rb')
        packet_data = pcap.Reader(fl)

        # 先处理Pcap包头，提取出时间和包的长度
        if packet_data == None:
            return
        # ts是timestemp时间戳，buf（二进制数据）是主体的数据包信息。
        for ts, buf in packet_data:
            pass

        '''
        解析包头主体数据buf
        '''
        # 格式时间戳为本地时间（元组形式表示的时间）
        datatime_ts = datetime.fromtimestamp(ts)    # 指定的时间戳创建一个datetime对象
        mytime = datatime_ts.strftime('%Y-%m-%d %H:%M:%S.%f')

        # 时间戳转为格式化的时间字符串
        # mytime = strftime('%Y-%m-%d %H:%M:%S', time_array)
        unpack_buf = hexdump(buf, length=16)
        # 计算开始抓包的绝对时间以及后续包的相对时间
        relative_time = float()
        relative_time = 0.0
        if self.packet_list:
            relative_time = ts - self.first_time
        else:
            self.first_time = ts

        re_pack = sub(r"(?<=\w)(?=(?:\w\w)+$)", "\n", str(unpack_buf))     # 用空格分开的16进制字符串

        '''
        包首部数据
        '''
        packet_context = {}         # 字典存储每一个包解析的全部内容
        pcap_header = {}
        pcap_header["Ptime"] = ts
        pcap_header["Relative Time"] = relative_time
        pcap_header["Time"] = str(mytime)
        pcap_header["Packet_len"] = (len(buf))
        pcap_header["Original_hex"] = str(re_pack)
        packet_context.update(pcap_header)


        fl.close()   # 不写的后果：PermissionError: [WinError 32] 另一个程序正在使用此文件，进程无法访问。: 'PyQt_scapy_dpkt_0.4\\packet\\.pcap'
        '''
        链路层
        '''
        # 链路层解析存储数据
        ethh_context = {"Destination MAC": 0, "Source MAC": 0, "Protocol": 8}
        # 数据部分以太帧读取
        ether = ethernet.Ethernet(buf)

        ethh_context["Destination MAC"] = mac_addr(ether.dst)
        ethh_context["Source MAC"] = mac_addr(ether.src)

        packet_context.update(ethh_context)

        # 判断网络层为ip
        if ether.type == ethernet.ETH_TYPE_IP:
            ###网络层
            ip = ether.data                 # 取ip数据包
            ver = ip.v                      # ip的版本号
            header_length = ip.hl           # ip的首部长度
            service = ip.tos                # ip服务类型
            length = ip.len                 # ip总长度

            iden = ip.id                    # 标识
            off = ip.off                    # 标志位 + 分片偏移
            offset = ip.offset              # 分片偏移量fragment offset
            rf = ip.rf                      # 标志：共3位。R、DF、MF三位。目前只有后两位有效，
            df = ip.df                      # DF位：为1表示不分片，为0表示分片。
            mf = ip.mf                      # MF位：为1表示“更多的片”，为0表示这是最后一片。

            # bytes字节流类型的IP地址转换为字符串类型
            src = inet_ntoa(ip.src)
            dst = inet_ntoa(ip.dst)
            ttl = ip.ttl                    # 存活时间
            protocol = tcp_or_udp[ip.p]
            proto = ip.p
            checksum = ip.sum               # 检验和

            # 网络层解析存储字典
            iph_context = {"IP Version": 4, "IP Header Length": 5, "TTL": 0, "Protocol": 1, "Checksum": 0, "Source": 0,
                            "Destination": 0}
            iph_context["IP Version"] = ver
            iph_context["IP Header Length"] = header_length
            iph_context["Type Of Service"] = service
            iph_context["IP Length"] = length
            iph_context["IP Identifier"] = iden
            iph_context["IP Flags"] = off
            iph_context["IP RF"] = str(rf)
            iph_context["IP DF"] = str(df)
            iph_context["IP MF"] = str(mf)
            iph_context["IP FOffset"] = offset
            iph_context["TTL"] = ttl
            iph_context["Proto"] = proto
            iph_context["Protocol"] = protocol
            iph_context["Source"] = src
            iph_context["Destination"] = dst
            iph_context["Checksum"] = checksum
            packet_context.update(iph_context)
            '''
            传输层
            '''
            tcudp = ip.data               # tcp数据包
            if isinstance(tcudp, tcp.TCP):
                sport = tcudp.sport       # 源端口号
                dport = tcudp.dport       # 目的端口号
                offset = tcudp.off        # 数据偏移
                sequence = tcudp.seq    
                ack = tcudp.ack
                flags = "{:#05x}".format(tcudp.flags)
                win = tcudp.win
                sum = tcudp.sum
                urp = tcudp.urp
                data = tcudp.data

                tcph_context = {"Source Port": 0, "Destination Port": 0, "Sequence Number": 0, "Acknowledge Number": 0,
                                "TCP Header Length": 0, "Window length": 0, "Checksum_tcp": 0, "Urgepkt": 0, "Data": 0}
                tcph_context["Source Port"] = sport
                tcph_context["Destination Port"] = dport
                tcph_context["Sequence Number"] = sequence
                tcph_context["Acknowledge Number"] = ack
                tcph_context["TCP Header Length"] = offset
                tcph_context["flags"] = flags
                tcph_context["window"] = win

                tcph_context["Data Length"] = len(data)

                packet_context.update(tcph_context)

                self.packet_list.append(packet_context)

            else:
                non = {"Data": 0, "Data Length": 0}
                packet_context.update(non)
                print("Protocol is not TCP")

parse = Parse()

class Table_View(APIView):
    def get(self, request):
        """
        后端上传和前端接收数据
        """
        global thread_flag
        if thread_flag == True:
            global pack_num
            pack_num = 0

            parse.__init__()
            parse.del_file()
            t = Thread(target=parse.run)
            t.setDaemon(True)           # 主线程A中，创建了子线程B，并且在主线程A中调用了B.setDaemon(),
                                        # 这个的意思是，把主线程A设置为守护线程，这时候，要是主线程A执行结束了，就不管子线程B是否完成,
                                        # 一并和主线程A退出
            t.start()
            thread_flag = False         # 设置该线程是否已经创建

        result = {
            "code":0,
            "msg":"success",
            "count":1000,
            "data":packet_data_list
        }
        result = json.dumps(result)
        return HttpResponse(result)


class Stop(APIView):
    def get(self, request):
        """
        设置开启Parse类中的Thread线程属性，该属性为Scapy.SendRecv.sniff嗅探函数的停止抓包条件
        """
        parse.stop_sending.set()
        result = {
            "code":0,
            "msg":"success",
            "count":1000,
        }
        result = json.dumps(result)
        return HttpResponse(result)