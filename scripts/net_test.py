# import socket
# import time
# tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# server_addr = ("127.0.0.1", 6201)
# tcp_socket.connect(server_addr)
# time.sleep(0.5)
# send_data = "connect ok?"
# tcp_socket.sendall(send_data.encode())
# resp = tcp_socket.recv(1024)
# print("resp: ")
# print(resp)
# print("test end")
#

import socket
import threading

TOTOAL_REQ = 4096
THREAD_NUM = 8

def tcp_client(host, port):
    try:
        # 创建TCP套接字
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # 连接服务器
        client_socket.connect((host, port))
        # print(f"Connected to {host}:{port}")

        # 发送数据
        for i in range(int(TOTOAL_REQ / THREAD_NUM)):
            message = "connect ok?"
            client_socket.sendall(message.encode())
            data = client_socket.recv(1024)
            print(f"Received from server: {data.decode()}")


        # 关闭套接字
        client_socket.close()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    # 服务器地址和端口
    server_host = '127.0.0.1'
    server_port = 6201

    # 建立64个TCP连接
    for i in range(THREAD_NUM):
        # 创建线程
        thread = threading.Thread(target=tcp_client, args=(server_host, server_port))
        # 启动线程
        thread.start()