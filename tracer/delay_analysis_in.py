from __future__ import print_function

import sys
from time import sleep

import argparse
from socket import inet_ntop, AF_INET
from struct import pack
import time

from bcc import BPF


########## constants and arrays ##########
res = []
interval=1000   #时间间隔
percentile=0.95 #观察值前95%的位置
############## arguments #################
parser = argparse.ArgumentParser(description="Trace time delay in network subsystem",
    formatter_class=argparse.RawDescriptionHelpFormatter)   #创建了一个 ArgumentParser 对象，追踪网络子系统中的时间延迟
#命令行参数
parser.add_argument("--sport", help="trace this source port only")  #仅追踪此源端口
parser.add_argument("-i","--interval",help="print ave,median at specified interval")    #在指定间隔打印平均值和中位数
parser.add_argument("--dport", help="trace this destination port only") #仅追踪此目的端口
parser.add_argument("-p","--percentile",default=0.9,help="print the top percentile as specified")   #按指定的百分位打印前百分比
parser.add_argument("--print", action="store_true", help="print results to terminal")   #将结果打印到终端
#parser.add_argument("-c", "--count", type=int, default=99999999, help="count of outputs")
parser.add_argument("--visual", action="store_true", help="enable visualization with influxdb-grafana") #输出结果用grafana演示
args = parser.parse_args()

bpf_text = open('delay_analysis_in.c').read()   //读取文件用于网络数据包过滤的 C 代码

# -------- code substitutions --------
# --sport
if args.sport:
    bpf_text = bpf_text.replace('##FILTER_SPORT##', 'if (pkt_tuple.sport != %s) { return 0; }' % args.sport)
    
if args.dport:
    bpf_text = bpf_text.replace('##FILTER_DPORT##', 'if (pkt_tuple.dport != %s) { return 0; }' % args.dport)

if args.interval:
    interval=1000*float(args.interval)

if args.percentile:
    percentile = float(args.percentile)

if args.visual:
    from utils import export_delay_analysis_in

# if args.visual:
#     from utils import export_delay_analysis_in

bpf_text = bpf_text.replace('##FILTER_SPORT##', 'if (pkt_tuple.sport == 0) { return 0; }')
bpf_text = bpf_text.replace('##FILTER_DPORT##', 'if (pkt_tuple.dport == 0) { return 0; }')

##############output files#################
file = open("./output/delay_analysis_in.txt", "w")
original_stdout = sys.stdout
sys.stdout = file


################## printer for results ###################
def print_event(cpu, data, size):
    event = b["timestamp_events"].event(data)
    res.append(int(event.total_time/1000))
    if args.print:
        print("%-22s %-22s %-12s %-12s %-10s %-10s %-10s %-10s" % (
            "%s:%d" % (inet_ntop(AF_INET, pack('I', event.saddr)), event.sport),
            "%s:%d" % (inet_ntop(AF_INET, pack('I', event.daddr)), event.dport),
            "%d" % (event.seq),
            "%d" % (event.ack),
            "%d" % (event.total_time/1000),
            "%d" % (event.mac_time/1000),
            "%d" % (event.ip_time/1000),
            "%d" % (event.tcp_time/1000)
        ))
    if args.visual:
        export_delay_analysis_in(event)


def calc_average(percentile=0.9):
    length = len(res)
    tot_time = 0
    res.sort()
    median = res[length//2]
    tail_latency = res[int(length*percentile)]
    while (len(res) > 0):
        cur = res.pop(0)
        tot_time += cur
    avg = tot_time/length
    return avg,median,tail_latency
    
################## start tracing ##################
b = BPF(text=bpf_text)
# adapte "ip_rcv_core" and "ip_crv_core.isra." via regular expression
b.attach_kprobe(event_re="^ip_rcv_core$|^ip_rcv_core\.isra\.\d$", fn_name="kernel_kprobe_ip_rcv_core")

if args.print:
    # -------- print header --------
    print("%-22s %-22s %-12s %-12s %-10s %-10s %-10s %-10s" % 
        ("SADDR:SPORT", "DADDR:DPORT", "SEQ", "ACK", "TOTAL", "MAC", "IP", "TCP"))

# -------- read events --------
b["timestamp_events"].open_perf_buffer(print_event)

count = 0

start_time = time.time_ns()//1000000

while 1:

    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
    
    now = time.time_ns()//1000000
    if (now - start_time) > interval:
        avg,median,tail_latency=calc_average(percentile)
        print("average time: %lf ,median time: %d,tail latency: %d" %(avg,median,tail_latency))
        start_time = now