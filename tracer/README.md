# 基于eBPF的Linux network kernel stack性能监测工具



## 1. 准备工作

Environment:
* 系统：Ubuntu 22.04
* 内核: 6.2-amd64
* Python 3.9.2
* bcc

## 2. 应用
### 2.1 delay_analysis

Print the average time, median time, and 90% percentile tail latency <b>every one second</b>. Analyze the delay for each packet,respectively.

参数如下：
```

--sport
    [可选] 指定源端口(default: include any source but NIC lo)
--dport
    [可选] 指定目的端口(default: include any destination but NIC lo)

--print
    [可选] output to a file in /output
```

运行示例 `sudo python3 delay_analysis_in.py --print --dport 80`




