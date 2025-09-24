注意事项
测试client时，要先在PC端执行iperf -s -i 1，再执行AT+NCSTART命令。否则，可能导致PC端收不到数据。

tcp iperf具体操作步骤：
1.烧录bin文件。
2.使能AP
	AT+WAP=0,6,a,qqqqqqqq			使能AP，0表示不保存至flash，1为保存，其余为channel，ssid和密码，非加密时无需输入密码
	使能AP后，用手机或者笔记本连上AP
3. tcp client测试命令
    AT+NCSTART=192.168.1.102,10  参数分别为server address（PC端的IP地址）,测试时间（单位为秒）
    测试结束返回+ok。
	手机端 iperf -s -i 1
    如果不输入时间，默认时间为无穷大。
4. tcp server测试命令
    AT+NSSTART
    测试结束返回+ok。
	手机端 iperf -c 192.168.66.1 -w1M -i 1 -t 1000 
	-t 1000 后边的参数是发包个数
5. 如果要轮流测试client和server,每次测试输入对应的测试命令即可。
