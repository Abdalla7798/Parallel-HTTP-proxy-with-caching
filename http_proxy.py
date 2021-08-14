import os
import socket
import sys
import enum
import re
import threading

hashmap = {}

class HttpRequestInfo(object):

    def __init__(self, client_info, method: str, requested_host: str,
                 requested_port: int,
                 requested_path: str,
                 headers: list):
        self.method = method
        self.client_address_info = client_info
        self.requested_host = requested_host
        self.requested_port = requested_port
        self.requested_path = requested_path
        self.headers = headers

    def to_http_string(self):
        to_server_request = 'GET ' + self.requested_path + " HTTP/1.0\r\n"
        for header_line in self.headers:
            to_server_request += header_line[0] + ": " + header_line[1] + "\r\n"
        to_server_request += "\r\n"
        return to_server_request


    def to_byte_array(self, http_string):
        return bytes(http_string, "UTF-8")


    def display(self):
        print(f"Client:", self.client_address_info)
        print(f"Method:", self.method)
        print(f"Path:", self.requested_path)
        print(f"Host:", self.requested_host)
        print(f"Port:", self.requested_port)
        stringified = [": ".join([k, v]) for (k, v) in self.headers]
        print("Headers:\n", "\n".join(stringified))


class HttpErrorResponse(object):

    def __init__(self, code, message):
        self.code = code
        self.message = message

    def to_http_string(self):
        error_string = 'HTTP/1.0 ' + self.code + ' ' + self.message + "\r\n\r\n"
        return error_string

    def to_byte_array(self, http_string):
        return bytes(http_string, "UTF-8")

    def display(self):
        print(self.to_http_string())


class HttpRequestState(enum.Enum):
    INVALID_INPUT = 0
    NOT_SUPPORTED = 1
    GOOD = 2
    PLACEHOLDER = -1


def find_response(http_request_info: HttpRequestInfo, key, client_connection, client_address):
    try:
        response_message = hashmap[key]
        client_connection.send(response_message.encode("utf-8"))
        client_connection.close()

    except:
        # the key does not exist in hashmap
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print("waiting for web server connection")
        try:
           server_socket.connect((http_request_info.requested_host, http_request_info.requested_port))
           print("web server ready to accept proxy request")
           server_socket.send(http_request_info.to_byte_array(http_request_info.to_http_string()))
           response_message = ""
           while True:
              data = server_socket.recv(4096)
              if len(data) > 0:
                 response_message += data.decode("utf-8")
              else:
                  break
           client_connection.send(response_message.encode("utf-8"))
           hashmap[key] = response_message
           server_socket.close()
           client_connection.close()
        except:
            error = HttpErrorResponse("408","Request timeout")
            client_connection.send(error.to_byte_array(error.to_http_string()))
            client_connection.close()


def serve_client(client_connection, client_address):
    client_request = ''
    print(f"proxy ready to receive request from client", client_address[1])
    while True:
        data = client_connection.recv(1024)  # Recieves data from Socket
        data = data.decode("utf-8")
        if data == '\r\n':
                client_request = client_request + data
                break
        else:
            client_request = client_request + data
    the_http_object = http_request_pipeline(client_address, client_request)

    if type(the_http_object) == HttpErrorResponse:
        error_message = the_http_object.to_byte_array(the_http_object.to_http_string())
        client_connection.send(error_message)
        client_connection.close()
    else:
        key = the_http_object.requested_host + "_" + the_http_object.requested_path
        find_response(the_http_object, key, client_connection, client_address)


def entry_point(proxy_port_number):
    socket = setup_sockets(proxy_port_number)
    while True:
        client_connection, client_address = socket.accept()
        threading._start_new_thread(serve_client,(client_connection,client_address))


def setup_sockets(proxy_port_number):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_address = ("127.0.0.1", proxy_port_number)
    sock.bind(server_address)
    sock.listen(50)
    return sock


def http_request_pipeline(source_addr, http_raw_data):
    http_returned_state = check_http_request_validity(http_raw_data)
    if http_returned_state == HttpRequestState.NOT_SUPPORTED:
        error_not_supported = HttpErrorResponse("501", "Not Implemented")
        return error_not_supported
    if http_returned_state == HttpRequestState.INVALID_INPUT:
        return HttpErrorResponse("400", "Bad Request")
    else:
        parsed = parse_http_request(source_addr, http_raw_data)
        modified_request = sanitize_http_request(parsed)
        return modified_request


def parse_http_request(source_addr, http_raw_data) -> HttpRequestInfo:
    http_request = http_raw_data.split('\r\n')
    first_line = http_raw_data.split('\r\n')[0]
    method = first_line.split(' ')[0]
    url = first_line.split(' ')[1]
    host = ""
    port = 80
    headers = list()

    for i in range(1, len(http_request) - 2):
        header_line = http_request[i].split(': ')
        headers.append([header_line[0], header_line[1]])
    # relative url
    if url[0] == '/':
        for header_line in headers:
            if (header_line[0].casefold() == "Host".casefold()):
                host = header_line[1]
                if host.find(":")!=-1:
                    port = int(host.split(':')[1])
                break
    # absolute url
    else:
        double_slash_po = url.find('//')
        if double_slash_po == -1:
            host = url.split('/')[0]
        else:
            host = url.split('//')[1].split('/')[0]
        if host.find(":") != -1:
            port = int(host.split(':')[1])

    ret = HttpRequestInfo(source_addr, method, host, port, url, headers)
    return ret

def check_http_request_validity(http_raw_data) -> HttpRequestState:

    http_request = http_raw_data.split('\r\n')
    first_line = http_raw_data.split('\r\n')[0]
    if "HTTP/1.0" not in first_line:
        return HttpRequestState.INVALID_INPUT
    method = first_line.split(' ')[0]

    if method != "GET" and method not in {"POST", "HEAD", "PUT", "DELETE"}:
        return HttpRequestState.INVALID_INPUT

    url = first_line.split(' ')[1]
    if re.match("^(http://www.|http://|https://www.|https://|www\.|(?!www)[a-z0-9]+)([a-z0-9]"
                "+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(/.*)?$)",url):
           if url.find('//')!=-1:
               url_part = url.split("//")[1]
               if url_part.find('//')!=-1 or len(url_part.split("/"))<2:
                  return HttpRequestState.INVALID_INPUT
           else:
               if url.find('//')!=-1 or len(url.split("/"))<2:
                  return HttpRequestState.INVALID_INPUT

           host_url = ""
           host_header = ""
           find = False
           host = True
           if url.find('//')!=-1:
               host_url = (url.split("//")[1]).split("/")[0]
           else:
               host_url = url.split("/")[0]

           for i in range(1, len(http_request) - 2):
               header_line = http_request[i].split(': ')
               if (header_line[0].casefold() == "Host".casefold()):
                   find = True
                   if (len(header_line)>=2):
                       host_header = header_line[1]
                       break
                   else:
                       host = False
                       break

           if find == True:
                if (host_url.split(":")[0]!=host_header.split(":")[0] or host==False):
                    return HttpRequestState.INVALID_INPUT

                temp = host_header.split(":")
                if len(temp)>=2:
                    if re.match("^[0-9]+$",temp[1])==False:
                        return HttpRequestState.INVALID_INPUT

    elif url[0] == "/" and url.find("//")==-1:
        host = False
        for i in range(1, len(http_request) - 2):
            header_line = http_request[i].split(': ')
            if (header_line[0].casefold() == "Host".casefold()):
                if (len(header_line)>=2):
                    if header_line[1] != "":
                        temp = header_line[1].split(":")
                        if len(temp)<2: #does not write ":"
                            host = True
                            break
                        elif re.match("^[0-9]+$",temp[1])==False:
                            host = True
                            break

        if host == False:
            return HttpRequestState.INVALID_INPUT
    else:
        return HttpRequestState.INVALID_INPUT

    header = True
    for i in range(1, len(http_request) - 2):
        header_line = http_request[i].split(': ')
        if (len(header_line)<2):
            header = False
            break
        elif header_line[0]=="" or header_line[1]=="":
            header = False
            break

    if header == False:
        return HttpRequestState.INVALID_INPUT

    if method in {"POST", "HEAD", "PUT", "DELETE"}:
        return HttpRequestState.NOT_SUPPORTED

    return HttpRequestState.GOOD


def sanitize_http_request(request_info: HttpRequestInfo) -> HttpRequestInfo:

    path_line = ""
    host = ""
    if re.match("^(http://www.|http://|https://www.|https://|www\.|(?!www)[a-z0-9]+)([a-z0-9]"
                "+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(/.*)?$)", request_info.requested_path):
        double_slash_po = request_info.requested_path.find('//')
        if double_slash_po == -1:
            host = request_info.requested_path.split('/')[0]
            path = request_info.requested_path.split('/')[1:]
            for p in path:
                path_line += '/'
                path_line += p

        else:
            host = request_info.requested_path.split('//')[1].split('/')[0]
            path = request_info.requested_path.split('//')[1].split('/')[1:]
            for p in path:
                path_line += '/'
                path_line += p

        request_info.requested_path = path_line

        find = False
        for head_line in request_info.headers:
            if (head_line[0].casefold() == "Host".casefold()):
                find = True
                break

        if find == False:
            request_info.headers.insert(0, ["Host",host])

        return request_info

    else:
        return request_info


def get_arg(param_index, default=None):
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The comand-line argument #[{param_index}] is missing")
            exit(-1)  # Program execution failed.


def check_file_name():
    script_name = os.path.basename(__file__)
    matches = re.findall(r"(\d{4}_){2}lab2\.py", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")


def main():
    print("*" * 50)
    print(f"[LOG] Printing command line arguments [{', '.join(sys.argv)}]")
    check_file_name()
    print("*" * 50)

    # This argument is optional, defaults to 18888
    proxy_port_number = get_arg(1, 18888)
    entry_point(int(8001))


if __name__ == "__main__":
    main()