数字中南跨平台登陆器

使用前需要安装argparse这个包:

pip install argparse

WINDOWS : csu_client.py -h    可以显示帮助信息

LINUX : ./csu_client.py -h    同上

使用说明：

1 : 使用csu_client.py进行登陆

WINDOWS : csu_client.py

LINUX/MAC : sudo ./csu_client.py

然后输入账号密码

2 : 使用csu_client.py令它机登陆(虽然这个功能没什么卵用)

WINDOWS : csu_client.py -i IP地址

LINUX/MAC : ./csu_client.py -i IP地址

2 : 使用csu_client.py令本机下线

WINDOWS : csu_client.py -o

LINUX/MAC : sudo ./csu_client.py -o

3 : 使用csu_client.py令它机下线

WINDOWS : csu_client.py -o -i IP地址

LINUX/MAC : ./csu_client.py -o -i IP地址
