"""
解析数据包
"""
import datetime
import socket
import sys
import time
from struct import *

import dpkt
from dpkt.compat import compat_ord
from dpkt.dpkt import hexdump
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtWidgets import QApplication
from scapy.sendrecv import sniff
from scapy.utils import wrpcap

tcp_or_udp = {}
tcp_or_udp[6] = 'tcp'
tcp_or_udp[17] = 'udp'
tcp_or_udp[1] = 'icmp'
tcp_or_udp[2] = 'igmp'
# 用字典存储一个包解析的全部内容
packet_context = {}
i = 0


def mac_addr(address):
    """
    将Mac地址转换为可读字符串
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)


class Sniffer(QThread):
    signal = pyqtSignal()

    def __init__(self, fil, parent=None):
        super(Sniffer, self).__init__(parent)
        self.packet_list = []
        self.fil = fil

    def run(self):
        """
        嗅探开启
        """
        sniff(prn=lambda x: self.parse_packet(x), filter=self.fil, count=18)

    def get_pack(self):
        pack = self.packet_list.pop(-1)  # PS：index = -1，删除最后一个列表值
        return pack

    def parse_packet(self, packet):
        """
        包解析
        """
        global i
        i = i + 1
        file = 'C:\python\PyQt_scapy_dpkt_0.1\packet\pack' + str(i)
        filename = file + '.pcap'
        wrpcap(filename, packet)

        fl = open(filename, 'rb')
        packet_data = dpkt.pcap.Reader(fl)

        '''
        pcap文件包头解析
        先处理Pcap包头，提取出时间和包的长度
        '''
        # ts是timestemp时间戳，buf（二进制数据）是主体的数据包信息。
        for ts, buf in packet_data:
            pass

        # 包头解析存储数据

        # 格式时间戳为本地时间（元组形式表示的时间）
        time_array = time.localtime(ts)
        # 时间戳转为格式化的时间字符串
        mytime = time.strftime("%Y-%m-%d %H:%M:%S", time_array)

        pcap_header = {}
        unpack_buf = hexdump(buf, length=16)
        pcap_header["Time"] = str(mytime)
        pcap_header["Packet_len"] = str(len(buf))
        pcap_header["Original_hex"] = str(unpack_buf)
        packet_context.update(pcap_header)

        ###链路层
        # 链路层解析存储数据
        ethh_context = {"Destination MAC": 0, "Source MAC": 0, "Protocol": 8}
        # 数据部分以太帧读取
        ether = dpkt.ethernet.Ethernet(buf)

        ethh_context["Destination MAC"] = mac_addr(ether.dst)
        ethh_context["Source MAC"] = mac_addr(ether.src)

        packet_context.update(ethh_context)

        # 判断网络层为ip
        if ether.type == dpkt.ethernet.ETH_TYPE_IP:
            ###网络层
            ip = ether.data  # 取ip数据包
            ver = ip.v  # ip的版本号
            header_length = ip.hl  # ip的首部长度
            id = ip.id  # ip的标识符
            src = socket.inet_ntoa(ip.src)  # bytes字节流类型的IP地址转换为字符串类型
            dst = socket.inet_ntoa(ip.dst)
            ttl = ip.ttl  # 存活时间
            off = hex(ip.off)  # 标识flags
            offset = hex(ip.offset)  # 分片偏移量
            protocol = tcp_or_udp[ip.p]
            checksum = ip.sum  # 检验和

            # 网络层解析存储字典
            iph_context = {"IP Version": 4, "IP Header Length": 5, "TTL": 0, "Protocol": 1, "Checksum": 0, "Source": 0,
                           "Destination": 0}
            iph_context["IP Version"] = str(ver)
            iph_context["IP Header Length"] = str(header_length)
            iph_context["TTL"] = str(ttl)
            iph_context["Protocol"] = str(protocol)
            iph_context["Source"] = src
            iph_context["Destination"] = dst
            iph_context["Checksum"] = str(checksum)
            packet_context.update(iph_context)
            ###传输层
            tcudp = ip.data  # tcp和udp的数据包
            if isinstance(tcudp, dpkt.tcp.TCP):
                sport = str(tcudp.sport)  # 源端口号
                dport = str(tcudp.dport)  # 目的端口号
                offset = tcudp.off  # 数据偏移
                sequence = "{:#010x}".format(tcudp.seq)  # 序列号，获取4字节的十六进制数
                ack = "{:#010x}".format(tcudp.ack)  # 确认号，获取4字节的十六进制数
                flags = "{:#06x}".format(tcudp.flags)  # 标志，获取2字节的十六进制数
                win = "{:#06x}".format(tcudp.win)  # 窗口大小，获取2字节的十六进制数
                sum = "{:#06x}".format(tcudp.sum)  # 检验和，获取2字节的十六进制数
                urp = "{:#06x}".format(tcudp.urp)  # 紧急指针，获取2字节的十六进制数
                data = tcudp.data

                tcph_context = {"Source Port": 0, "Destination Port": 0, "Sequence Number": 0, "Acknowledge Number": 0,
                                "TCP Header Length": 0, "Window length": 0, "Checksum_tcp": 0, "Urgepkt": 0, "Data": 0}
                tcph_context["Source Port"] = str(sport)
                tcph_context["Destination Port"] = str(dport)
                tcph_context["Sequence Number"] = str(sequence)
                tcph_context["Acknowledge Number"] = str(ack)
                tcph_context["TCP Header Length"] = str(off)
                tcph_context["Window length"] = str(win)
                tcph_context["Checksum_tcp"] = str(sum)
                tcph_context["Urgepkt"] = str(urp)
                tcph_context["Data"] = str(data)

                packet_context.update(tcph_context)
                self.packet_list.append(packet_context)

            elif isinstance(tcudp, dpkt.udp.UDP):
                sourceport = tcudp.sport
                destinport = tcudp.dport
                userpacket_length = tcudp.ulen
                checksum_udp = tcudp.sum
                data = tcudp.data

                udph_context = {"Souce port": 0, "Destination port": 0, "User packet length": 0, "Checksum UDP": 0,
                                "Data": 0}
                udph_context["Souce port"] = str(sourceport)
                udph_context["Destination port"] = str(destinport)
                udph_context["User packet length"] = str(userpacket_length)
                udph_context["Checksum UDP"] = str(checksum_udp)
                udph_context["Data"] = str(data)

                packet_context.update(udph_context)
                self.packet_list.append(packet_context)

            elif isinstance(tcudp, dpkt.icmp.ICMP):
                icmp_type = tcudp.type      # 类型：占一字节，标识ICMP报文的类型，目前已定义了14种，从类型值来看ICMP报文可以分为两大类。第一类是取值为1~127的差错报文，第2类是取值128以上的信息报文。
                code = tcudp.code           # 代码：占一字节，标识对应ICMP报文的代码。它与类型字段一起共同标识了ICMP报文的详细类型。
                checksum_icmp = tcudp.sum   # 校验和：这是对包括ICMP报文数据部分在内的整个ICMP数据报的校验和，以检验报文在传输过程中是否出现了差错。其计算方法与在我们介绍IP报头中的校验和计算方法是一样的。
                identifier = tcudp.Echo.id       # 标识：占两字节，用于标识本ICMP进程，但仅适用于回显请求和应答ICMP报文，对于目标不可达ICMP报文和超时ICMP报文等，该字段的值为0。
                sequence_icmp = tcudp.Echo.seq

                icmph_context = {"ICMP Type": 0, "ICMP Code": 0, "ICMP Checksum": 0, "Identifier": 0, "Sequence": 0}
                icmph_context["ICMP Type"] = str(icmp_type)
                icmph_context["ICMP Code"] = str(code)
                icmph_context["ICMP Checksum"] = str(checksum_icmp)
                icmph_context["Identifier"] = str(identifier)
                icmph_context["Sequence"] = str(sequence_icmp)
                icmph_context["Data"] = str(data)

                packet_context.update(icmph_context)
                self.packet_list.append(packet_context)

            else:
                non = {"Data": 0}

                packet_context.update(non)
                self.packet_list.append(packet_context)
                print("Protocol is not TCP,ICMP,UDP")
        self.signal.emit()
            


if __name__ == "__main__":
    app = QApplication(sys.argv)
    sniffer = Sniffer('{0F761049-52DF-48FC-954C-9AEF70011A72}')
    sniffer.run()
    sys.exit(app.exec_())
