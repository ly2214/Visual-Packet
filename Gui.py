# /usr/bin/env python3
# coding: utf-8

""" 
“import Tkinter”：引用这个模块中的方法时要带上模块“Tkinter.方法”；
“from Tkinter import * ”：可省略模块名；
（PS：貌似是一个命名空间的问题。如果这段代码中还有其他模块中的方法与该模块中的方法重名，则第二种导入方法会出问题。）
“import Tkinter as xx（这里名字随意，相当于替代，button2 = xx.Button（））”：既不需要敲全模块名，又可以防止不同模块方法名重复的冲突。
"""

import re
from copy import deepcopy

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtGui import QStandardItem, QStandardItemModel
from PyQt5.QtWidgets import (QAbstractItemView, QHeaderView, QTableWidgetItem,
                             QTreeWidget, QTreeWidgetItem)

import Parse


'''
父类UI
'''
class Ui_Main(object):
    cap_sig = pyqtSignal(str)
    text_sig = pyqtSignal(str)
    tree_sig = pyqtSignal(dict)
    row_sig = pyqtSignal(list)
    # cap_sig.emit(string)
    # button.clicked.connect(self.func)
    Signel = pyqtSignal(int, str) #打开子窗口

    def __init__(self):
        self.pack_list = []
        self.pack_hex_store = []

   
    def setupUi(self, Main):
        '''
        整体UI的设计
        '''
        Main.setObjectName("Main")
        Main.setWindowTitle('sniffer')
        
        # 主分布布局
        # 用于添加其它布局
        # 包括：
        # 工具栏control_vbox QHBoxLayout
        # 列举包的列表packet_table QTableWidget
        # 协议解析包区域details_hbox QHBoxLayout
        self.widget = QtWidgets.QWidget(Main)
        Main.setCentralWidget(self.widget)
        self.widget.setObjectName("widget")

        self.main_layout = QtWidgets.QVBoxLayout(self.widget)
        self.main_layout.setContentsMargins(10, 10, 10, 10)
        self.main_layout.setSpacing(10)
        self.main_layout.setObjectName("main_layout")

        # 水平布局QHBoxLayout
        # 工具栏
        self.control_vbox = QtWidgets.QHBoxLayout(self.widget)
        self.control_vbox.setContentsMargins(10, 10, 10, 10)
        self.control_vbox.setSpacing(10)
        self.control_vbox.setObjectName("control_vbox")

        # 按钮QPushBotton
        # 用于捕获包
        self.sniff_button = QtWidgets.QPushButton(self.widget)
        self.sniff_button.setObjectName("sniff_button")
        self.control_vbox.addWidget(self.sniff_button)
        self.cap_sig.connect(self.capture_start)                # 捕获包
        self.sniff_button.clicked.connect(self.emit_cap_sig)    # 发送捕获包的信号

        # 行文本QLineEdit
        # 用于填写过滤规则
        self.filter_input = QtWidgets.QLineEdit(self.widget)           
        self.filter_input.setObjectName("filter_input")
        self.control_vbox.addWidget(self.filter_input)

        # 按钮QPushButton
        # 用于过滤
        self.filter_button = QtWidgets.QPushButton(self.widget)        
        self.filter_button.setObjectName("filter_button")
        self.control_vbox.addWidget(self.filter_button)
        self.main_layout.addLayout(self.control_vbox)
        self.filter_button.clicked.connect(self.emit_cap_sig)

        # 按钮QPushButton
        # 用于暂停
        self.quit_button = QtWidgets.QPushButton(self.widget)          
        self.quit_button.setObjectName("filter_button")
        self.control_vbox.addWidget(self.quit_button)
        self.main_layout.addLayout(self.control_vbox)

        # 列表QTableWidget
        # 用于列举包
        self.packet_table = QtWidgets.QTableWidget(self.widget)
        self.packet_table.setObjectName("packet_table")
        self.main_layout.addWidget(self.packet_table)
        #self.packet_table.verticalHeader().setVisible(False)                             # 设置垂直表头隐藏
        self.packet_table.setColumnCount(6)
        self.packet_table.setHorizontalHeaderLabels([ "Time", "Source", "Destination", "Protocol", "Length", "Info"])
        self.packet_table.horizontalHeader().setStretchLastSection(True)                  # 表格填满窗口
        #self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)   # 是否拉伸
        self.packet_table.setEditTriggers(QAbstractItemView.NoEditTriggers)               # 设置表格不能被修改
        self.packet_table.setSelectionBehavior(QAbstractItemView.SelectRows)              # 设置表格为整行选中

        # ----------------------------------------------------------------
        # ----------------------增加--------------------------------------------
        self.packet_table.doubleClicked.connect(self.sync_table_double_clicked)
        #----------------------- -----------------------------------------------
        #----------------------- -----------------------------------------------

        self.packet_table.itemClicked.connect(self.get_row)                   

        # 协议解析包区域QHBoxLayout
        self.details_hbox = QtWidgets.QHBoxLayout(self.widget)
        self.details_hbox.setObjectName("details_hbox")

        # 该区域添加的树状数据结构QTreeWidget
        self.tree = QtWidgets.QTreeWidget(self.widget)             # 树形结构
        self.tree.setObjectName("tree_text")
        self.tree.setHeaderHidden(False)
        self.details_hbox.addWidget(self.tree)
        self.tree.setColumnCount(1)

        # 该区域添加的解析区信息QPlainTextEdit
        # 用于列举包的详细信息
        self.details_text = QtWidgets.QPlainTextEdit(self.widget)
        self.details_text.setObjectName("details_text")
        self.details_hbox.addWidget(self.details_text)
        self.details_text.setReadOnly(True)                # 设为只读

        self.main_layout.addLayout(self.details_hbox)

        self.retranslateUi(Main)
        QtCore.QMetaObject.connectSlotsByName(Main)


        # ----------------------------------------------------------------
        # ----------------------增加--------------------------------------------
    def sync_table_double_clicked(self, index):
        # table_column = index.column()
        # table_row = index.row()
        # current_item = self.packet_table.item(table_row, table_column)
        # current_widget = self.packet_table.cellWidget(table_row, table_column)
        # print("---------------------------------------------------------")
        # print(current_item.text())
        # print("---------------------------------------------------------")
        dialog = tcp.Dialog(self)
        # =================
        self.Signel.connect(dialog.slot)
        self.Signel.emit(0,"11111")
        # =========================
        dialog.show()
        # -------------------------------------------------------------------

    def retranslateUi(self, Main):
        _translate = QtCore.QCoreApplication.translate
        Main.setWindowTitle(_translate("Main", "Sniffer"))
        self.sniff_button.setText(_translate("Main", "Catch"))
        self.filter_button.setText(_translate("Main", "Filter"))
        self.quit_button.setText(_translate("Main", "Quit"))



    def get_row(self):
        '''
        获取选中的包的行号    
        QTableWidget.selectedItems()
        QTableWidget.indexFromItem().row()
        text_sig.emit()
        tree_sig.emit()
        '''
        self.selectedRow = list()
        item = self.packet_table.selectedItems()
        for i in item:
            if self.packet_table.indexFromItem(i).row() not in self.selectedRow:
                self.selectedRow.append(self.packet_table.indexFromItem(i).row())
        row_num = self.selectedRow[0]       # 点击得到当前行的行号

        self.packet_table.itemClicked.connect(self.get_trigger)       # 按钮连接文本数据更新触发——自定义文本信号text_sig连接
        self.text_sig.emit(self.pack_hex_store[row_num])
        self.packet_table.itemClicked.connect(self.get_trigger_tree)  # 按钮连接树型数据更新触发——自定义文本信号tree_sig连接
        self.tree_sig.emit(self.pack_list[row_num])


    def emit_cap_sig(self):
        '''
        抓包信号cap_sig发射
        self.cap_sig.connect(self.capture_start)
        filter_button.clicked.connect(self.emit_cap_sig)
        '''
        self.cap_sig.emit(str(self.filter_input.text()))
    def capture_start(self, f):
        '''
        捕获包按钮响应事件 sniff_button.clicked.connect(self.emit_cap_sig)
        过滤包按钮响应事件 filter_button.clicked.connect(self.emit_cap_sig)
        '''
        self.sniff = Parse.Sniffer(f)
        self.sniff.signal.connect(self.pack_receive)
        self.sniff.run()
    def pack_receive(self):
        pack_copy = {}
        pack = self.sniff.get_pack()
        pack_copy = deepcopy(pack)
        self.pack_list.append(pack_copy)
        pack_hex = pack['Original_hex'] # 数据包的十六进制字符串
        self.pack_hex_store.append(pack_hex)
        if pack != None:
            ptime = pack["Time"]
            src = pack["Source"]
            dst = pack["Destination"]
            ptcl = pack["Protocol"]
            plen = pack['Packet_len']
            info = pack["Data"]
            self.updatable1(ptime, src, dst, ptcl, plen, info)

    def updatetable(self, plist):

        '''
        包列表的数据更新
        '''
        for p in plist:
            if p != None:
                self.updatable1(p['Time'],p['Source MAC Address'],p['Destination MAC Addrss'],p['Protocol'],p['Packet_len'],p['Data'])
    def updatable1(self, ptime, src, dst, ptcl, plen, info):
        '''
        QTableWidget.rowCount()
        QTableWidget.insertRow()
        QTableWidget.setItem()
        '''
        row = self.packet_table.rowCount() #获取行数
        self.packet_table.insertRow(row)   #插入增加一行
        #QTableWidget.setItem(行，列，组件)
        self.packet_table.setItem(row, 0, QTableWidgetItem(ptime))
        self.packet_table.setItem(row, 1, QTableWidgetItem(src))
        self.packet_table.setItem(row, 2, QTableWidgetItem(dst))
        self.packet_table.setItem(row, 3, QTableWidgetItem(ptcl))
        self.packet_table.setItem(row, 4, QTableWidgetItem(plen))
        self.packet_table.setItem(row, 5, QTableWidgetItem(info))

    
    def get_trigger(self):
        '''
        文本数据更新触发
        '''
        self.running = True  # 槽触发标识符
        self.text_sig.connect(self.updatetext)
    def updatetext(self, pack_hex):
        '''
        16进制数据包内容显示在文本框details_text中。
        .QPlainTextEdit.set/append/insertPlainText()
        '''
        if self.running == True:
            '''
            正则表达式re.sub()？？？

            '''
            re_pack = re.sub(r"(?<=\w)(?=(?:\w\w)+$)", " ", pack_hex)  # 用空格分开的16进制字符串
            self.details_text.setPlainText("")                         # 清空之前的字符
            self.details_text.appendPlainText("re information:\n" + re_pack + "\n")
            self.details_text.insertPlainText("hexdump inforamtion:\n" + pack_hex + "\n")
            self.running = False

    
    def get_trigger_tree(self):
        '''
        树数据更新触发
        '''
        self.running = True  # 槽触发标识符
        self.tree_sig.connect(self.updatetree)
    def updatetree(self, pack):
        '''
        树型协议解析区QTreeWidgetItem
        '''
        self.tree.clear()
        root1 = QTreeWidgetItem(self.tree)
        root1.setText(0, "Frame: " + str(pack["Packet_len"])+ " bytes")
        child1 = QTreeWidgetItem(root1)
        child1.setText(0, "Arrival Time: " + str(pack["Time"]) + '\n' + "Frame Length: " + str(pack["Packet_len"]) + "bytes")

        root2 = QTreeWidgetItem(self.tree)
        root2.setText(0, "Ethernet,Src: " + str(pack["Source MAC"]) + ", Dst: " + str(pack["Destination MAC"]))
        child2 = QTreeWidgetItem(root2)
        child2.setText(0, "Source Mac: "+str(pack['Source MAC']) + '\n' + "Destination MAC: " + str(pack["Destination MAC"]) + "\n" + "Protocol: " + str(pack["Protocol"]))

        '''
        UDP
        root3: Internet Protocol Version
        child3:
        IP Header Length
        Time to live
        Source IP Address
        Destination IP Address
        Protocol
        Header Checksum
        
        root4: User Datagram数据报 Protocol
        child4: UDP详细信息
        '''
        '''
        TCP
        root3: Internet Protocol Version
        child3:
        IP Header Length
        Time to live
        Source IP Address
        Destination IP Address
        Protocol
        Header Checksum

        root4: Transmission Protocol
        child4:
        Source Port
        Destination Port
        Sequence Number
        Acknowledge Number
        Header Length
        Window length
        Checksum_tcp
        Urgepkt
        '''
        '''
        ICMP
        root3: Internet Protocol Version
        child3: IP Header Length

        root4: Transmission Protocol
        child4: 
        Source Port
        Destination Port
        Sequence Number
        Acknowledge Number
        Header Length
        Window length
        Checksum_tcp
        Urgepkt
        '''
        if str(pack['Protocol']) == 'udp':
            root3 = QTreeWidgetItem(self.tree)
            root3.setText(0, "Internet Protocol Version " + str(pack["IP Version"]) + ", Src: " + str(
                    pack['Source']) + ", Dst" + str(pack['Destination']))
            child3 = QTreeWidgetItem(root3)
            child3.setText(0, "IP Header Length: " + str(
                int(str(pack['IP Header Length'])) * 4) + "\n" + "Time to live: " + str(pack['TTL']) + "\n" + "Source IP Address: " + str(
                    pack["Source"]) + "\n" + "Destination IP Address: " + str(
                    pack['Destination']) + "\nProtocol: " + str(
                    pack['Protocol']) + "\nHeader Checksum: " + str(pack['Checksum']))

            root4 = QTreeWidgetItem(self.tree)
            root4.setText(0, "User Datagram Protocol, Src Port: " + str(pack['Souce port']) + "Dst Port: " + str(pack['Destination port']))
            child4 = QTreeWidgetItem(root4)
            child4.setText(0, "Source Port: " + str(pack['Souce port']) + "\n" + 'Destination Port: ' + str(pack['Destination port']) + \
                           "\n" + "Length: " + str(pack['User packet length']) + "\nChecksum: " + str(pack['Checksum UDP']))

        elif str(pack['Protocol']) == 'tcp':
            root3 = QTreeWidgetItem(self.tree)
            root3.setText(0, "Internet Protocol Version " + str(pack["IP Version"]) + ", Src: " + str(
                pack['Source']) + ", Dst" + str(pack['Destination']))
            child3 = QTreeWidgetItem(root3)
            child3.setText(0, "IP Header Length: " + str(
                int(str(pack['IP Header Length'])) * 4) + "\n" + "Time to live: " + str(
                pack['TTL']) + "\n" + "Source IP Address: " + str(
                pack["Source"]) + "\n" + "Destination IP Address: " + str(
                pack['Destination']) + "\nProtocol: " + str(
                pack['Protocol']) + "\nHeader Checksum: " + str(pack['Checksum']))

            root4 = QTreeWidgetItem(self.tree)
            root4.setText(0, "Transmission Protocol, Src Port: " + str(pack['Source Port']) + ",Dst Port: " + str(pack['Destination Port']))
            child4 = QTreeWidgetItem(root4)
            child4.setText(0, "Source Port: " + str(pack['Source Port']) + "\n" + 'Destination Port: ' + str(pack['Destination Port']) + \
                           "\n" + "Sequence Number: " + str(pack['Sequence Number']) + "\nAcknowledge Number: " + str(pack['Acknowledge Number']) +\
                           "\nTCP Header Length: " + str(pack['TCP Header Length']) + "\nWindow length: " + str(pack['Window length']) +\
                           "\nChecksum: " + str(pack['Checksum_tcp']) + "\nUrgent pointer: " + str(pack['Urgepkt']))

        elif str(pack['Protocol']) == 'icmp':
            root3 = QTreeWidgetItem(self.tree)
            root3.setText(0, "Internet Protocol Version " + str(pack["IP Version"]) + ", Src: " + str(
                pack['Source']) + ", Dst" + str(pack['Destination']))
            child3 = QTreeWidgetItem(root3)
            child3.setText(0, "IP Header Length: " + str(
                int(str(pack['IP Header Length'])) * 4) + "\n" + "Time to live: " + str(
                pack['TTL']) + "\n" + "Source IP Address: " + str(
                pack["Source"]) + "\n" + "Destination IP Address: " + str(
                pack['Destination']) + "\nProtocol: " + str(
                pack['Protocol']) + "\nHeader Checksum: " + str(pack['Checksum']))

            root4 = QTreeWidgetItem(self.tree)
            root4.setText(0, "Internet Control Message Protocol")
            child4 = QTreeWidgetItem(root4)
            child4.setText(0, "Type: " + str(pack["ICMP Type"]) + "\nCode: " +
                        str(pack["ICMP Code"]) +"\nChecksum: " + str(pack["ICMP Checksum"]) + "\nIdentifier: " + str(pack["Identifier"] + "\nSequenct Numver: " + str(pack["Sequence"])))

        elif str(pack["Protocol"]) == "arp":
            root3 = QTreeWidgetItem(self.tree)
            root3.setText(0,"Address Resolution Protocol " )
            child3 = QTreeWidgetItem(root3)
            child3.setText(0, "Hardware type: " + str(pack["Hardware type"]) + '\n' + "Protocol type: " + str(pack["Protocol type"]) + "\n" + \
                           "Hardware size: " + str(pack["Hardware size"]) + '\n' + "Protocol size: " + str(pack["Protocol Size"]) + "\n" +\
                           "Opcode: " + str(pack["Opcode"]) + '\n' + "Sender MAC Address: " + str(pack["Source"]) + "\n" +\
                           "Sender IP Address: " + str(pack["Source IP Address"]) + "\n" + "Target MAC Address: " + str(pack["Destination"]) + '\n' +\
                           "Target IP Address: " + str(pack["Target IP Address"]))
