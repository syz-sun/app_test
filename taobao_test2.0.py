# -*- encoding=utf8 -*-
__author__ = "Administrator"

from airtest.core.api import *

from airtest.core.api import *
import os
import time
import multiprocessing
import threading
auto_setup(__file__)

print('hi im taobao')


def clear_iptables_rule():
    #清空全部的iptables历史规则
    print('clear iptables rules')
    os.system("adb -s 721QAC2D33337 shell su su iptables -F")



def close_back_process():
    system='meizu_note2'
    ###清理后台运行

    if system=='meizu_note2':
        cmd = "adb -s 721QAC2D33337 shell input tap 850 1870"     #点击菜单按钮
        os.system(cmd)
        cmd = "adb -s 721QAC2D33337 shell input tap 560 1750"    #点击屏幕的“X”号
        os.system(cmd)
    time.sleep(0.3)


def get_userId(package_name):
    ##首先获取package_name对应的userid
    os.system("adb -s 721QAC2D33337 root")
    cmd = "adb -s 721QAC2D33337 shell dumpsys package {0} | findstr userId".format(package_name)
    print(cmd)
    userId = os.popen(cmd).readlines()
    if len(userId) > 0:
        userId = int(userId[0].strip().split(" ")[0].split("=")[-1])
        return userId
    return  0 #找不到应用

def add_iptables_rule(userId):
    ###添加NFLOG的iptables规则
    clear_iptables_rule()
    os.system(
        "adb -s 721QAC2D33337 shell su su iptables -A OUTPUT -m owner --uid-owner {0} -j CONNMARK --set-mark {0}".format(
            userId))
    os.system(
        "adb -s 721QAC2D33337 shell su su iptables -A INPUT -m connmark --mark {0} -j NFLOG --nflog-group {0}".format(
            userId))
    os.system(
        "adb -s 721QAC2D33337 shell su su iptables -A OUTPUT -m connmark --mark {0} -j NFLOG --nflog-group {0}".format(
            userId))

def get_versionName(package):
    #获取app版本号
    cmd ="adb -s 721QAC2D33337 shell dumpsys package {0}| findstr versionName".format(package)
    output=os.popen(cmd).readlines()
    if len(output) == 0:
        raise BaseException('{0} does not exist'.format(package))
    return  output[0].strip().split("=")[-1]

def pullpcap(timestamp,dst_dir):
    print("pull pcap files to local host.")
    #获取数据
    os.system("adb -s 721QAC2D33337 pull /sdcard/app_traffic/{0}_clear.pcap {1}/{2}_clear.pcap".format(timestamp,dst_dir,timestamp))
    os.system("adb -s 721QAC2D33337 pull /sdcard/app_traffic/{0}_noise.pcap {1}/{2}_noise.pcap".format(timestamp, dst_dir, timestamp))
    #删除数据
    os.system("adb -s 721QAC2D33337 shell rm /sdcard/app_traffic/{0}_clear.pcap".format(timestamp))
    os.system("adb -s 721QAC2D33337 shell rm /sdcard/app_traffic/{0}_noise.pcap".format(timestamp))

def open_tcpdump(userId,timestamp):
    #开启抓包进程tcpdump
    os.system("adb -s 721QAC2D33337 shell su su pkill  tcpdump")
    if userId!=0:
        cmd = "adb -s 721QAC2D33337 shell su su /data/tcpdump -i nflog:{0} -w /sdcard/app_traffic/{1}_clear.pcap".format(userId,timestamp)
    else:
        cmd = "adb -s 721QAC2D33337 shell su su /data/tcpdump -i wlan0 -w /sdcard/app_traffic/{1}_noise.pcap".format(userId,timestamp)
    print(cmd)
    os.system(cmd)

def dumppcap(package_name,timestamp):
    #多进程抓取数据
    userId = get_userId(package_name)
    if userId==0:
        return  0
    #if userId == 0 :
    #    raise  BaseException('package %s does not exist.'%package_name)
    add_iptables_rule(userId)
    t1 = threading.Thread(target=open_tcpdump,args=(userId,timestamp))
    t1.start()
    t2 = threading.Thread(target=open_tcpdump,args=(0,timestamp))
    t2.start()
    return userId

def close(package_name,userId):
    #关闭app
    print('force stop app running.')
    os.system("adb -s 721QAC2D33337 shell am force-stop %s" % package_name)
    #os.system("adb shell pkill -U {0}".format(userId))
    time.sleep(1)
    os.system("adb  -s 721QAC2D33337 shell input keyevent KEYCODE_HOME")
    close_back_process()


def close_tcpdump():
    #关闭抓包进程tcpdump
    cmd = "adb -s 721QAC2D33337 shell su su pkill  tcpdump"

    os.system(cmd)
    print(cmd)
    time.sleep(1)
    clear_iptables_rule()
    time.sleep(1)

def operator(package_name):
    #启动并测试app
    if package_name=='com.taobao.taobao':
        start_app("com.taobao.taobao")
        wait(Template(r"tpl1603163550179.png", record_pos=(-0.191, -0.601), resolution=(1080, 1920)))
        touch(Template(r"tpl1603163565624.png", record_pos=(-0.187, -0.602), resolution=(1080, 1920)))
        sleep(3)
        touch(Template(r"tpl1603165233470.png", record_pos=(0.308, -0.769), resolution=(1080, 1920)))
        sleep(2)
        touch(Template(r"tpl1603165353646.png", record_pos=(-0.124, -0.769), resolution=(1080, 1920)))

        text("手机")
        sleep(5)

def capture_main(package_name):
    timestamp = int(time.time())
    # package_name = 'com.taobao.taobao'

    userId = dumppcap(package_name, timestamp)
    # 启动并测试app
    operator(package_name)
    #关闭app
    close(package_name, userId)
    #关闭抓包进程
    close_tcpdump()
    # 获取app版本号
    versionName = get_versionName(package_name)
    dst_dir = pcap_destination_dir+"{0}/{1}/".format(package_name,versionName)
    if not os.path.exists(dst_dir):
        os.makedirs(dst_dir)
    pullpcap(timestamp,dst_dir)
    print('using {0} seconds'.format(int(time.time())-timestamp))

pcap_destination_dir ="D:/SYZ1/taobao/android_meizu_note2_2020_10_29/"

# for i in range(3):
#     timestamp = int(time.time())
#     package_name='com.taobao.taobao'
#
#     userId = dumppcap(package_name,timestamp)
#     # userId=get_userId('com.taobao.taobao')
#     # add_iptables_rule(userId)
#     print('timestamp',timestamp)
#
#
#
#     #启动并测试app
#     operator(package_name)
#
#
#
#     # wait(Template(r"tpl1603163550179.png", record_pos=(-0.191, -0.601), resolution=(1080, 1920)))
#     # touch(Template(r"tpl1603163565624.png", record_pos=(-0.187, -0.602), resolution=(1080, 1920)))
#     # sleep(3)
#     # touch(Template(r"tpl1603165233470.png", record_pos=(0.308, -0.769), resolution=(1080, 1920)))
#     # sleep(2)
#     # touch(Template(r"tpl1603165353646.png", record_pos=(-0.124, -0.769), resolution=(1080, 1920)))
#     #
#     # text("手机")
#     # sleep(5)
#
#     #关闭app
#     close(package_name, userId)
#     #关闭抓包进程
#     close_tcpdump()
#
#     # os.system("adb  -s 721QAC2D33337 shell input keyevent KEYCODE_HOME")
#     # close_back_process()
#     # os.system("adb -s 721QAC2D33337 shell su su pkill  tcpdump")
#
#     print('timestamp:',timestamp)
#     #获取app版本号
#     versionName = get_versionName(package_name)
#
#     dst_dir = pcap_destination_dir+"{0}/{1}/".format(package_name,versionName)
#     if not os.path.exists(dst_dir):
#         os.makedirs(dst_dir)
#     pullpcap(timestamp,dst_dir)
#     print('using {0} seconds'.format(int(time.time())-timestamp))
app_list=['com.taobao.taobao']

for i in range(1):
    for app in app_list:
        for i in range(3):
            try:
                capture_main(app)
            except BaseException as exp:
                print('Error :', exp)
