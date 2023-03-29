"""
    Multithreaded websocket proxy to fuzz unknown endpoints, params or sqlmap proxy.
    Coded By: nriver
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
from websocket import create_connection
from urllib.parse import urlparse
from socketserver import ThreadingMixIn
from argparse import ArgumentParser
from urllib.parse import urlparse, unquote
from sys import argv
import string, random, hashlib, json

# web status codes
STATUS_CODE_UNKNOWN = 0
STATUS_CODE_OK = 200
STATUS_CODE_BAD_REQUEST = 400
STATUS_CODE_NOT_FOUND = 404
# module names
PATH_FUZZING_MODE = 'path'
PARAM_FUZZING_MODE = 'param'
SQLMAP_FUZZING_MODE = 'sqlmap'
# not found compute constants
MAX_TESTS = 10
RANDOM_PARAM_LEN = 5

"""
    Generate random params/paths to understand the
    "NOT FOUND" context response.
"""
def get_not_found_response():
    outputs = {}

    def get_random_string():
        letters = string.ascii_lowercase
        return ''.join(random.choice(letters) for i in range(RANDOM_PARAM_LEN))

    def send_message(wsocket, message):
        ws = create_connection(wsocket)
        ws.send(message)
        resp = ws.recv()
        ws.close()
        return resp
    
    # compute response digest, and store its frequency
    for i in range(MAX_TESTS):
        hasher = hashlib.new('sha256')
        if args.module == PATH_FUZZING_MODE:    
            try:
                ws_path = args.websocket + get_random_string()
                response = send_message(ws_path, json.dumps({'foo':'bar'}))
            except:
                continue
        elif args.module == PARAM_FUZZING_MODE:
            try:
                ws_path = args.websocket
                response = send_message(ws_path, json.dumps({get_random_string():'bar'}))
            except:
                continue
        hasher.update(response.encode())
        response_digest = hasher.hexdigest()
        if response_digest in outputs.keys():
            outputs[response_digest]['frequency'] += 1
        else:
            outputs[response_digest] = {
                'frequency': 1,
                'content': response
            }
    # compute max frequency not found response
    max_frequency_output = None
    for key in outputs.keys():
        if max_frequency_output is None or outputs[key]['frequency'] > max_frequency_output['frequency']:
            max_frequency_output = outputs[key]
    return max_frequency_output


def fuzz_route(route):    
    ws_server = args.websocket + route
    try:
        ws = create_connection(ws_server)
        # test json message to send
        message = json.dumps({'foo': 'bar'})
        ws.send(message)
        resp = ws.recv()
        ws.close()
    except Exception:
        return (False, '')
    return (True, resp) if resp != not_found_response['content'] else (False, '')


def fuzz_param(param):    
    try:
        ws = create_connection(args.websocket)
        # test json message to send
        message = json.dumps({param: 'value'})
        ws.send(message)
        resp = ws.recv()
        ws.close()
    except Exception:
        return (False, '')
    return (True, resp) if resp != not_found_response['content'] else (False, '')


def fuzz_sqlmap(sqli):
    ws = create_connection(args.websocket)
    #message = unquote(sqli).replace('"','\'')
    # in case victim used double quotes intead of single quote -.-
    message = unquote(sqli).replace('\'','"') 
    data = json.dumps({args.param_name: message})
    ws.send(data)
    resp = ws.recv()
    ws.close()
    return (True,resp) if resp else (False,'')


class WSWebServer(BaseHTTPRequestHandler):
    
    def do_GET(self):
        it_exists, content = False, ''
        status_code = STATUS_CODE_UNKNOWN
        try:
            data = urlparse(self.path).query.split('=',1)[1]
            if args.module == PATH_FUZZING_MODE:
                it_exists, content = fuzz_route(data)
            elif args.module == PARAM_FUZZING_MODE:
                it_exists, content = fuzz_param(data)
            elif args.module == SQLMAP_FUZZING_MODE:
                it_exists, content = fuzz_sqlmap(data) 
            status_code = STATUS_CODE_OK if it_exists else STATUS_CODE_NOT_FOUND
        except IndexError:
            status_code = STATUS_CODE_BAD_REQUEST
            self.wfile.write(b'')
        finally:
            self.send_response(status_code)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(content.encode())


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""


if __name__ == '__main__':
    # - Choice module to use
    if argv[1] == PATH_FUZZING_MODE: 
        parser = ArgumentParser(usage='python3 wsfuzz.py path --ws "ws://ws.server.htb:9000/" --lhost 127.0.0.1 --lport 6060')
        # compute not found response based on module loaded
        print('computing not found response ...')
        not_found_response = get_not_found_response()
    elif argv[1] == PARAM_FUZZING_MODE:
        parser = ArgumentParser(usage='python3 wsfuzz.py param --ws "ws://ws.server.htb:9000/endpoint" --lhost 127.0.0.1 --lport 6060')
        # compute not found response based on module loaded
        print('computing not found response ...')
        not_found_response = get_not_found_response()
    elif argv[1] == SQLMAP_FUZZING_MODE:
        parser = ArgumentParser(usage='python3 wsfuzz.py path --ws "ws://ws.server.htb:9000/endpoint" --pname version --lhost 127.0.0.1 --lport 6060')
        parser.add_argument("--pname",dest="param_name",action="store",type=str,required=True,help="Param name to fuzz")
    else:
        print('Unknown module. Exit!')
        exit(-1)

    # parse common args
    parser.add_argument("module")
    parser.add_argument("--ws",dest="websocket",action="store",type=str,required=True,help="Insert the websocket for the test")
    parser.add_argument("--lhost",dest="host",action="store",type=str,required=True,default="127.0.0.1",help="Enter your ip. Default=127.0.0.1")
    parser.add_argument("--lport",dest="port",action="store",type=int,required=True,default="80",help="Enter your port. Default=80")
    # parser.add_argument("--wsmessage",dest="wsmessage",action="store",type=str,required=False,default="",help="Enter your expected default websocket message when enpoint is not found")
    args = parser.parse_args()
    
    # start multi-threaded server
    print('starting ws proxy ...')
    server = ThreadedHTTPServer((args.host, args.port), WSWebServer)
    server.serve_forever()