import socket
tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_addr = ("127.0.0.1", 6201)
tcp_socket.connect(server_addr)
send_data = "connect ok?"
tcp_socket.send(send_data.encode("utf8"))
print("test end")
