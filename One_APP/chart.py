import json
import os
import sys
import socket
from math import ceil
from itertools import groupby
from copy import deepcopy
from pyecharts import options as opts
from pyecharts.charts import Bar, Line, Sankey, Parallel, Graph, Scatter, Tab


global packet_data_list
packet_data_list = []               # 抓包分析到的原始数据


class ChartFactory:
    def __init__(self):
        self._func = {}
        self._charts = {}
        self.packet_list = []                   # 主界面获取的整个抓取的包

    def collect(self, name):
        # 搭配@回调返回生成Pyecharts函数
        def _inject(func):
            self._func[name] = func
            return func
        return _inject

    def create(self, name):
        # 视图类调用接口函数，选择指定的图表生成器
        global packet_data_list
        packet_data_list = deepcopy(self.packet_list)
        if name in self._func:
            chart = self._func[name]()
            return chart
        else:
            raise ValueError('No Chart builder for {}'.format(name))
# 前端和后端调用的实例
CHART = ChartFactory()


# @装饰器，修饰下面的函数（作为参数）
# 调用函数：FACTORY.create('line_seq')
@CHART.collect('line_seq')
def line_base():
    '''
    TCP的stevens绘制
    调用类：Charts_Seq
    '''
    selected_pack_list = [] # 被选中的数据包在该tcp流中的所有数据包
    seq_list = []           # 分析得到的tcp流中的相对序列号
    time_rela_list = []     # 分析得到的tcp流中的相对时间
    first_time = None       # 暂时指定为某一个传输线路，后期值得商榷
    src_adr = None          # 暂时指定为某一个传输线路，后期值得商榷
    des_adr = None          # 暂时指定为某一个传输线路，后期值得商榷

    # with open('test.txt', "w") as f:  
    #         f.write(str(packet_data_list))

    if(packet_data_list):
        sorted_packet_list = sorted(packet_data_list, key=lambda x: (x["Source"], x["Destination"]))
        grouped_packet_list = groupby(sorted_packet_list, key=lambda x: (x["Source"], x["Destination"]))
        group_list = []
        for key, group in grouped_packet_list:
            group = list(group)
            group_list.append(group)
        
        line_dic = {}
        tab = Tab()

        for i, lis in zip(range(len(group_list)), group_list):    
            # 列表添加时间和序列号的数据
            timed_pack_list = sorted(lis, key=lambda x: x["Ptime"])
            first_time = lis[0]["Ptime"]       # 指定该线路的起始传输时间
            src_adr = lis[0]['Source']         # 该线路的源地址
            des_adr = lis[0]['Destination']    # 该线路的目的地址
            time_rela_list.clear()
            seq_list.clear()

            length = len(timed_pack_list)
            for j in range(len(timed_pack_list)):
                pack = timed_pack_list[j]
                relative_time = pack["Ptime"] - first_time
                time_rela_list.append(relative_time)

                relative_seq = pack["Relative Sequence Number"]
                seq_list.append(relative_seq)

            line = (
                Line()
                .add_xaxis(time_rela_list)
                .add_yaxis('', seq_list, is_step=True, label_opts=opts.LabelOpts(is_show=False))
                .extend_axis(
                    yaxis=opts.AxisOpts(
                        type_="value",
                        name='',
                        axisline_opts=opts.AxisLineOpts(
                            linestyle_opts=opts.LineStyleOpts(color="#675bba")
                        ),
                        axislabel_opts=opts.LabelOpts(formatter="{value}"),
                        splitline_opts=opts.SplitLineOpts(
                            is_show=True, linestyle_opts=opts.LineStyleOpts(opacity=1)
                        ),
                    )
                )
                .set_global_opts( 
                    tooltip_opts=opts.TooltipOpts(trigger="axis", axis_pointer_type="cross"),
                    title_opts=opts.TitleOpts(title='Stevens for ' + src_adr + '→' + des_adr),
                    datazoom_opts=opts.DataZoomOpts(type_="inside" # 整体缩放
                                ,range_start=0                     # 显示区域的开始位置，默认是20
                                ,range_end=100                     # 显示区域的结束位置，默认是80
                                # ,orient='vertical'               # 缩放区域空值条所放的位置                     
                                ),
                    xaxis_opts=opts.AxisOpts(
                        name='Time(s)',
                        splitline_opts=opts.SplitLineOpts(is_show=True),
                        name_location='center',
                        name_gap = 35,
                        type_="value"
                    ),
                    yaxis_opts=opts.AxisOpts(
                        name='Sequence Number(B)',
                        name_location='center',
                        name_rotate=90,
                        name_gap = 55,
                    ),
                    toolbox_opts = opts.ToolboxOpts(
                        is_show=True,
                        pos_top="top",
                        pos_left="right",
                        feature={"saveAsImage": {} ,
                            "restore": {} ,
                            "magicType":{"show": True, "type":["line","bar"]},
                            "dataView": {} }
                        )
                )
            )
            name = str(src_adr) + '→' + str(des_adr)
            tab.add(line, name)
        line_dic = {
            'data':tab.render_embed()
        }
        return line_dic
    else:
        return


# @装饰器，修饰下面的函数（作为参数）
# 调用函数：FACTORY.create('Graph_seq')
@CHART.collect('Graph_seq')
def graph_base():
    '''
    TCPFlow的绘制（关系图）
    调用类：TCPFlow_View
    '''
    timed_group_list = []       # 分析得到的有序的包
    group_node = []             # 集合所有的端口结点        
    categories = []             # 每个结点设定为一个类别
    category_flag = 0           # 设定的类别值，每次加一
    node = []
    link = []
    option = {}
    
    if(packet_data_list):
        sorted_packet_list = sorted(packet_data_list, key=lambda x: (x["Source"], x["Destination"]))
        grouped_packet_list = groupby(sorted_packet_list, key=lambda x: (x["Source"], x["Destination"]))
        group_list = []
        for key, group in grouped_packet_list:
            group = list(group)
            group_list.append(group)
        
        # 合并源地址和目的地址相反的两个list
        new_group_list = []
        for i in range(len(group_list)):
            left_pack_list = group_list[i]
            start_postion = i + 1
            if start_postion<=len(group_list):
                for j in range(start_postion, len(group_list)):
                    right_pack_list = group_list[j]
                    if left_pack_list[0]['Source']==right_pack_list[0]['Destination'] and left_pack_list[0]['Destination']==right_pack_list[0]['Source']:
                        left_pack_list += right_pack_list
                        new_group_list.append(left_pack_list)

        # 按接发时间排序整个包列表————严格完善的端口间的通信
        for i in range(len(new_group_list)):
            timed_pack_list = sorted(new_group_list[i], key=lambda x: x["Ptime"])
            timed_group_list.append(timed_pack_list)

        for lis in timed_group_list:
            if lis[0]['Source'] not in group_node:
                group_node.append(lis[0]['Source'])
                node_source = {
                    'name': lis[0]['Source'],
                    'des': lis[0]['Source'],
                    'symbolSize': 100,
                    'category': category_flag,
                    }
                node.append(node_source)    
                category_flag = category_flag+1
            if lis[0]['Destination'] not in group_node:
                group_node.append(lis[0]['Destination'])
                node_destination = {
                    'name': lis[0]['Destination'],
                    'des': lis[0]['Destination'],
                    'symbolSize': 100,
                    'category': category_flag,
                    }
                node.append(node_destination)
                category_flag = category_flag+1

            syn_list = []
            count_ack = 0
            count_psh = 0
            for i, pack in zip(range(len(lis)), lis):
                if pack['flags'] == '0x010' and (pack["Relative Sequence Number"] != 1 or pack["Relative ACK Number"] != 1):
                    if count_ack == 0:
                        syn_list.append(pack)
                    count_ack += 1
                elif pack['flags'] == '0x018':
                    if count_psh == 0:
                        syn_list.append(pack)
                    count_psh += 1
                else:
                    syn_list.append(pack)
            
            with open('test.txt', "w") as f:
                f.write(str(syn_list))
                
            for i, pack in zip(range(len(syn_list)), syn_list):
                arc = 1-1/len(syn_list)*i
                if pack['flags'] == '0x002' or pack['flags'] == '0x012' or (pack['flags'] == '0x010' and pack["Relative Sequence Number"] == 1 and pack["Relative ACK Number"] ==1):
                    arc_link = {
                        'source': pack['Source'],
                        'target': pack['Destination'],
                        'name': str(i) + '. ' + pack['Info'],
                        'des': pack['Info'],
                        'lineStyle': {
                            'type': 'dashed',
                            'curveness': arc,
                            'width': 1,
                            'color': '#4b565b',
                            }
                    }
                    link.append(arc_link)

                elif pack['flags'] == '0x018':
                    arc_link = {
                        'source': pack['Source'],
                        'target': pack['Destination'],
                        'name': str(i) + '. ' + '[PSH] [ACK]' + ' counts:' + str(count_psh),
                        'des': pack['Info'],
                        'lineStyle': {
                            'type': 'solid', 
                            'curveness': arc,
                            'width': ceil(count_psh/10),
                            'color': '#4b565b',
                            }
                    }
                    link.append(arc_link)

                elif pack['flags'] == '0x010':
                    arc_link = {
                        'source': pack['Source'],
                        'target': pack['Destination'],
                        'name': str(i) + '. ' + '[ACK]' + ' counts:' + str(count_ack),
                        'des': pack['Info'],
                        'lineStyle': {
                            'type': 'solid',
                            'curveness': arc,
                            'width': ceil(count_ack/10),
                            'color': '#4b565b',
                            }
                    }
                    link.append(arc_link)

                else:
                    arc_link = {
                        'source': pack['Source'],
                        'target': pack['Destination'],
                        'name': str(i) + '. ' + pack['Info'],
                        'des': pack['Info'],
                        'lineStyle': {
                            'type': 'dotted',
                            'curveness': arc,
                            'width': 1,
                            'color': '#4b565b',
                            }
                    }
                    link.append(arc_link)

        for i in range(len(group_node)):
            dic = {
                'name': group_node[i]
            }
            categories.append(dic)

        option = {
            'node': node,
            'link': link,
            'categories': categories
        }

        return option
    else:
        return


# @装饰器，修饰下面的函数（作为参数）
# 调用函数：FACTORY.create('Sankey_IO')
@CHART.collect('Sankey_IO')
def sankey_base():
    '''
    IOgraph绘制
    调用函数：Chart_View
    '''
    timed_group_list = []       # 按端点分类的的包
    timed_numpacks_list = []    # 按时间分割的包数目列表
    time_list = []              # 时间点列表
    group_node = []             # 集合所有的端口结点        
    categories = []             # 每个结点设定为一个类别
    category_flag = 0           # 设定的类别值，每次加一
    nodes = []
    links = []
    option = {}
    
    if(packet_data_list):
        timed_packet_list = sorted(packet_data_list, key=lambda x: x["Ptime"])
        first_time = timed_packet_list[0]["Relative Time"]
        numpacks = 1
        for packet in timed_packet_list:
            subtraction = packet["Relative Time"]-first_time
            if subtraction<1:
                numpacks += 1
            else:
                timed_numpacks_list.append(numpacks)
                time_list.append(first_time)
                numpacks = 1
                first_time = packet["Relative Time"]

        sorted_packet_list = sorted(packet_data_list, key=lambda x: (x["Source"], x["Destination"]))
        grouped_packet_list = groupby(sorted_packet_list, key=lambda x: (x["Source"], x["Destination"]))
        group_list = []
        for key, group in grouped_packet_list:
            group = list(group)
            group_list.append(group)
        
        # 合并源地址和目的地址相反的两个list
        new_group_list = []
        for i in range(len(group_list)):
            left_pack_list = group_list[i]
            for j in range(len(group_list)):
                right_pack_list = group_list[j]
                if left_pack_list[0]['Source']==right_pack_list[0]['Destination'] and left_pack_list[0]['Destination']==right_pack_list[0]['Source']:
                    left_pack_list += right_pack_list
                    new_group_list.append(left_pack_list)

        # 按接发时间排序整个包列表————严格完善的端口间的通信
        for i in range(len(new_group_list)):
            timed_pack_list = sorted(new_group_list[i], key=lambda x: x["Ptime"])
            timed_group_list.append(timed_pack_list)

        for lis in timed_group_list:
            if lis[0]['Source'] not in group_node:
                group_node.append(lis[0]['Source'])
                node = {
                    'name': lis[0]['Source']
                    }
                nodes.append(node)
                
            if lis[0]['Destination'] not in group_node:
                group_node.append(lis[0]['Destination'])
                node = {
                    'name': lis[0]['Destination']
                    }
                nodes.append(node)

            dic = {'source': lis[0]['Source'], 'target': lis[0]['Destination'], 'value': len(lis)}
            links.append(dic)

        line = (
            Line()
            .add_xaxis(time_list)
            .add_yaxis('', timed_numpacks_list)
            .extend_axis(
                yaxis=opts.AxisOpts(
                    type_="value",
                    name='',
                    axisline_opts=opts.AxisLineOpts(
                        linestyle_opts=opts.LineStyleOpts(color="#675bba")
                    ),
                    axislabel_opts=opts.LabelOpts(formatter="{value}"),
                    splitline_opts=opts.SplitLineOpts(
                        is_show=True, linestyle_opts=opts.LineStyleOpts(opacity=1)
                    ),
                )
            )
            .set_global_opts(
                datazoom_opts=opts.DataZoomOpts(type_="inside" # 整体缩放
                            ,range_start=0                     # 显示区域的开始位置，默认是20
                            ,range_end=100                     # 显示区域的结束位置，默认是80
                            # ,orient='vertical'               # 缩放区域空值条所放的位置                     
                            ),
                title_opts=opts.TitleOpts(title='IO Graphs: Download'),
                xaxis_opts=opts.AxisOpts(
                    name='Time(s)',
                    splitline_opts=opts.SplitLineOpts(is_show=True),
                    name_location='center',
                    name_gap = 35,
                    type_="value"
                ),
                yaxis_opts=opts.AxisOpts(
                    name='packets/s',
                    splitline_opts=opts.SplitLineOpts(is_show=True),
                    name_location='center',
                    name_rotate=90,
                    name_gap = 35
                ),
                toolbox_opts = opts.ToolboxOpts(
                        is_show=True,
                        pos_top="top",
                        pos_left="right",
                        feature={"saveAsImage": {} ,
                            "restore": {} ,
                            "magicType":{"show": True, "type":["line","bar"]},
                            "dataView": {} }
                )
            )
            .dump_options_with_quotes()
        )

        sankey = (
            Sankey()
            .add(series_name=''
                ,nodes=nodes
                ,links=links
                ,linestyle_opt=opts.LineStyleOpts(opacity=0.2 # 透明度设置
                                            , curve=0.5       # 信息流的曲线弯曲度设置
                                            ,color="source"   # 颜色设置，source表示使用节点的颜色
                                            )                 # 线条格式 ,设置所有线条的格式
                ,label_opts=opts.LabelOpts(font_size=16
                                        ,position='right'
                                        )                # 标签配置，具体参数详见opts.LabelOpts()
                ,is_selected=True                        # 图例是否选中             
                ,pos_left='20%'                          # 图距离容器左边的距离             
                ,pos_top='20%'                           # 图距离容器上端的距离             
                ,pos_right='20%'                         # 图距离容器右侧的距离             
                ,pos_bottom='20%'                        # 图距离容器下端的距离 
                ,node_gap = 10                           # 节点之间的距离,(查看垂直图片的操作orient="vertical")
            )
            .set_global_opts(
                title_opts=opts.TitleOpts(title = 'IO Graphs: Packets'),
                toolbox_opts = opts.ToolboxOpts(
                        is_show=True,
                        pos_top="top",
                        pos_left="right",
                        feature={"saveAsImage": {} ,
                            "restore": {} ,
                            "dataView": {} }
                )
            )
            .dump_options_with_quotes()
        )

        series = {
            'line':line,
            'sankey':sankey
        }
        return series
    else:
        return


# @装饰器，修饰下面的函数（作为参数）
# 调用函数：FACTORY.create('Scatter_RTT')
@CHART.collect('Scatter_RTT')
def scatter_base():
    '''
    标准Bar生成写法
    调用函数：Chart_View
    '''
    timed_group_list = []                # 分析得到的有序的包
    Seq_xaxis_list = []
    seq_rtt_data_list = []

    tab = Tab()
    scatter_dic = {}
    scatter_list = []

    # 获取本机ip，计算从远程服务端发送的数据包传向本机后发送确认数据包的rtt
    ip = socket.gethostbyname(socket.gethostname())
    
    # 按源地址和目的地址分割list
    if(packet_data_list):
        sorted_packet_list = sorted(packet_data_list, key=lambda x: (x["Source"], x["Destination"]))
        grouped_packet_list = groupby(sorted_packet_list, key=lambda x: (x["Source"], x["Destination"]))
        group_list = []
        for key, group in grouped_packet_list:
            # print('---------------------------------------------------')
            # print(key)
            group = list(group)
            group_list.append(group)
        
        # 合并源地址和目的地址相反的两个list
        new_group_list = []
        for i in range(len(group_list)):
            left_pack_list = group_list[i]
            start_postion = i + 1
            if start_postion<=len(group_list):
                for j in range(start_postion, len(group_list)):
                    right_pack_list = group_list[j]
                    if left_pack_list[0]['Source']==right_pack_list[0]['Destination'] and left_pack_list[0]['Destination']==right_pack_list[0]['Source']:
                        left_pack_list += right_pack_list
                        new_group_list.append(left_pack_list)
        
        # 按接发时间排序整个包列表————严格完善的端口间的通信
        for i in range(len(new_group_list)):
            timed_pack_list = sorted(new_group_list[i], key=lambda x: x["Ptime"])
            timed_group_list.append(timed_pack_list)
        
        for j, lis in zip(range(len(timed_group_list)), timed_group_list):    
            seq_rtt_data_list.clear()
            src_adr = str()
            src_adr_temp = str()
            des_adr = str()
            des_adr_temp = str()

            for i, pack in zip(range(len(lis)), lis):
                src_adr_temp = pack['Source']
                des_adr_temp = pack['Destination']
                # 获取本机ip，计算从远程服务端发送的数据包传向本机后发送确认数据包的rtt
                if ip != des_adr_temp:
                    continue
                src_adr = src_adr_temp
                des_adr = des_adr_temp
                left_src_prt = pack['Source Port']
                Data_Length = pack['Data Length']
                Seq_xaxis = pack['Relative Sequence Number']
                flag = False  # 是否已经计算了该ack的RTT标志位——判断是否有重复ack读取
            
                # 判断是否已计算过该序列号的RTT
                if Data_Length != 0 and (Seq_xaxis not in Seq_xaxis_list):
                    Seq_xaxis_list.append(Seq_xaxis)
                    des_adr = pack['Destination']
                    DifferIndex_Time = pack['Ptime']
                    nextpack = i + 1
                    while(nextpack<len(lis)):
                        # 判断是否为同一端口下的数据包确认
                        right_dst_prt = lis[nextpack]['Destination Port']                     
                        if left_src_prt != right_dst_prt:
                            pass
                        else:
                            # 计算RTT
                            if lis[nextpack]['Relative ACK Number'] == Seq_xaxis + Data_Length and flag == False:
                                RTTime = (lis[nextpack]['Ptime'] - DifferIndex_Time)*1000
                                seq_rtt_data = {
                                    'rtt':RTTime,
                                    'seq':Seq_xaxis
                                }
                                seq_rtt_data_list.append(seq_rtt_data)
                                flag = True
                                break
                        nextpack+=1

                    # 没找到该包返回的ack（实际应该算超时来处理）
                    if flag==False:
                        pass
            
            if ip != des_adr and seq_rtt_data_list:
                continue
        
            x_data = [d['seq'] for d in seq_rtt_data_list]
            y_data = [d['rtt'] for d in seq_rtt_data_list]
            print('-------------------------------------------------')
            print(x_data)

            scatter = (
                Line()
                .add_xaxis(x_data)
                .add_yaxis('', y_data, label_opts=opts.LabelOpts(is_show=False))
                .extend_axis(
                    yaxis=opts.AxisOpts(
                        type_="value",
                        name='',
                        axisline_opts=opts.AxisLineOpts(
                            linestyle_opts=opts.LineStyleOpts(color="#675bba")
                        ),
                        axislabel_opts=opts.LabelOpts(formatter="{value}"),
                        splitline_opts=opts.SplitLineOpts(
                            is_show=True, linestyle_opts=opts.LineStyleOpts(opacity=1)
                        ),
                    )
                )
                .set_global_opts(
                    tooltip_opts=opts.TooltipOpts(trigger="axis", axis_pointer_type="cross"),
                    datazoom_opts=opts.DataZoomOpts(type_="inside" # 整体缩放
                                ,range_start=0                     # 显示区域的开始位置，默认是20
                                ,range_end=100                     # 显示区域的结束位置，默认是80
                                # ,orient='vertical'               # 缩放区域空值条所放的位置                     
                                ),
                    title_opts=opts.TitleOpts(title='Round Trip Time for '+src_adr+'→'+des_adr),
                    xaxis_opts=opts.AxisOpts(
                        name='Sequence Number(B)',
                        splitline_opts=opts.SplitLineOpts(is_show=True),
                        name_location='center',
                        name_gap = 35,
                        type_="value"
                    ),
                    yaxis_opts=opts.AxisOpts(
                        name='Round Trip Time(ms)',
                        name_location='center',
                        name_rotate=90,
                        name_gap = 35,
                    ),
                    toolbox_opts = opts.ToolboxOpts(
                        is_show=True,
                        pos_top="top",
                        pos_left="right",
                        feature={"saveAsImage": {} ,
                            "restore": {} ,
                            "magicType":{"show": True, "type":["line","bar"]},
                            "dataView": {} }
                    )
                )
            )
            tab.add(scatter, src_adr + '→' + des_adr)

        scatter_dic = {
            'data':tab.render_embed()
        }
        return scatter_dic
    else:
        return