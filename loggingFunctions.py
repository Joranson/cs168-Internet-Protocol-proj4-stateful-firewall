import re
import struct

def retrieveInfo(http_string, ip_addr): ## TODO: implement this             
            # suppose payload(in hex) has been unpacked to a string called http_string
            print http_string
            req_str, res_str = http_string.split("\r\n\r\n")[:2]
            req_str += "\r\n"
            res_str += "\r\n"
            result_dict = {}
            host = re.findall(r"Host: (?P<value>.*?)\r\n", req_str)
            result_dict["host"] = (host and host[0].rstrip())  or ip_addr
            result_dict["method"] = req_str.split()[0]
            result_dict["path"] = req_str.split()[1]
            result_dict["version"] = req_str.split()[2]
            result_dict["status_code"] = res_str.split()[1]
            obj_size = re.findall(r"Content-Length: (?P<value>.*?)\r\n", res_str)
            result_dict["object_size"] = (obj_size and obj_size[0].rstrip()) or "-1"

            return result_dict

def log(info):
            f = open('http.log', 'a')
            
            write_str = info["host"]+" "+info["method"]+" "+info["path"]+" "+info["version"]+" "+info["status_code"]+" "+info["object_size"]+"\n"
            print "string to write", write_str
            f.write(write_str)

def test():
    httpReq = "GET / HTTP/1.1\r\nHost: \r\nUserAgent:Websniffer/1.0.46 (+http://websniffer.net/\r\nAcceptEncoding:gzip\r\nCacheControl:nocache\r\n\r\n"
    httpRes = "HTTP/1.1 301 Moved Permanently\r\nLocation: http://www.google.com/\r\nContent-Length:\r\n\r\n"

    info = retrieveInfo(httpReq+httpRes, "1.1.1.1") 
    print info
    log(info)
