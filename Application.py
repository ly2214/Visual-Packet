
# /usr/bin/env python3
# coding: utf-8

import sys

from PyQt5.QtWidgets import QMainWindow, QApplication

from Gui import Ui_Main


class AppWindow(QMainWindow, Ui_Main):
    '''
    继承设计的UI界面
    运行该程序
    '''
    def __init__(self, parent=None):
        super(AppWindow, self).__init__(parent)
        self.setupUi(self)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    w = AppWindow()
    w.show()
    sys.exit(app.exec_())
