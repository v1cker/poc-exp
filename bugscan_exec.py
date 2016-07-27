#coding=utf8
# 2016.01.11 12:12:01

import sys

sys.dont_write_bytecode = True
import imp

import os
import marshal
import multiprocessing
import threading
import Queue
import time
import platform
import base64
import md5
import pickle
import logging
import signal
import binascii
import StringIO
import zlib
import socket
import traceback
import json
import urlparse
import httplib
import ssl
import uuid
import datetime
import thread
import struct


Debug_yes_no = False
Argv_5 = 5
sys_debug_yes_no = False
debug_key = None
Multiprocessing_RLock = multiprocessing.RLock()
Login_Get = None
Scan_ThreadLocal = threading.local()
I11, Oo0o0000o0o0, oOo0oooo00o, Range_3, oo0o0O00, Range_5, Range_6, oooOOOOO = range(8)
o00ooooO0oO, oOoOo00oOo, Oo, o00O00O0O0O = range(4)


def iIii1():
    def oOOoO0(chunk, modulename):
        II = imp.new_module(modulename)
        exec chunk in II.__dict__
        sys.modules[modulename] = II
        return II


iIii1()

import util
import DNS
import miniCurl
import threadpool
import decode


Mysql_Obj = None
Mysql_cursor = None
Queue_queue = Queue.Queue()#队列实例


def Debug_X(debugkey, where='fork'):
    global Mysql_Obj
    global Mysql_cursor
    if '45e11faade39ab147c52b4ed06fa66cc' == '45e11faade39ab147c52b4ed06fa66cc':
        try:
            if True:
                import MySQLdb

                Mysql_Obj = MySQLdb.connect(host='127.0.0.1', user='root', passwd='root', port=3306)
                Mysql_Obj.select_db('wsss')
                Mysql_cursor = Mysql_Obj.cursor()

                return True
        except Exception as o0oo0o0O00OO:

            pass


def Mysql_table_insert(dbtable, **kwargs):
    if Mysql_Obj and Mysql_cursor:
        try:
            iI = 'insert into %s(%s,date) values(%s, %s)' % (dbtable,
                                                             ','.join(kwargs.keys()),
                                                             ','.join(['%s'] * len(kwargs)),
                                                             '"%s"' % datetime.datetime.now())
            Queue_queue.put((iI, kwargs.values()))
        except Exception as o0oo0o0O00OO:
            pass


def Mysql_insert_QueueInfo():

    while Mysql_Obj and Mysql_cursor:
        iI, IF_exit = Queue_queue.get()#队列获取

        print "---duilie---", iI, IF_exit, "---duilie---"

        if 'exit' in IF_exit:
            break
        try:
            Mysql_cursor.execute(iI, IF_exit)
            Mysql_Obj.commit()
        except Exception as o0oo0o0O00OO:
            pass


def Get_lineNumber_fileName():

    File_Info_Class = sys._getframe().f_back

    lineNumber = File_Info_Class.f_lineno#获取当前行号

    funcName = File_Info_Class.f_code.co_name

    try:
        lineNumber_2 = File_Info_Class.f_back.f_lineno#获取当前行号
        funcName_FileName = File_Info_Class.f_back.f_code.co_name
    except:
        funcName_FileName = File_Info_Class.f_code.co_filename
        lineNumber_2 = lineNumber

    return '%s:%d <= %s:%d' % (funcName,
                               lineNumber,
                               funcName_FileName,
                               lineNumber_2)


class Log_StreamHandler(logging.StreamHandler):
    def emit(self, record):
        logging.StreamHandler(record)
        Mysql_table_insert('loglog', body=self.format(record))

String_IO = StringIO.StringIO()


def Logging():
    logging.basicConfig(stream=String_IO, format='%(levelname)-10s %(asctime)s %(message)s', level=logging.ERROR)

    Log_getLogget = logging.getLogger('__engine__')

    Log_StreamHandler_Obj = Log_StreamHandler()
    Log_StreamHandler_Obj.setLevel(logging.NOTSET)
    Log_StreamHandler_Obj.setFormatter(logging.Formatter('%(levelname)-10s %(asctime)s %(message)s'))

    Log_getLogget.addHandler(Log_StreamHandler_Obj)

    return Log_getLogget


Logging_Obj = Logging()


def Hook_x(type, value, tb):#异常处理钩子
    Logging_Obj.critical(''.join(traceback.format_exception(type, value, tb)))

sys.excepthook = Hook_x#当系统异常时会转发给Hook_x函数去处理


def Print_str(fmt, *args):
    global Debug_yes_no
    global sys_debug_yes_no
    global Multiprocessing_RLock

    if sys_debug_yes_no or sys.flags.debug or not Debug_yes_no:
        Multiprocessing_RLock.acquire()
        print fmt % args
        Multiprocessing_RLock.release()


if __name__ == '__main__' and sys.platform == 'win32':
    i1OOO = marshal.dumps(sys._getframe().f_code)


class SCAN_multiprocessing(object):
    @staticmethod
    def PProcess(func, args):
        if sys.platform != 'win32':
            return multiprocessing.Process(target=func, args=args)
        else:
            return multiprocessing.Process(target=eval, args=(
                "__import__('code').InteractiveInterpreter({'__args__':__args__, '__name__':'__fork__', '__func__':'%s'}).runcode(__import__('marshal').loads(_chunk))" % func.__name__,
                {'_chunk': i1OOO,
                 '__args__': args}))


    def __init__(self, maxtasks=200):
        self._pool = {}
        self._taskqueue = Queue.Queue()
        self._maxtasks = maxtasks


    def push(self, pid, target, args=(), callback=None, timeout=None):
        if pid in self._pool:
            return False
        else:
            self._taskqueue.put((pid,
                                 target,
                                 args,
                                 callback,
                                 timeout))
            self.poll()
            return True


    def idel(self):
        return self._maxtasks - self._taskqueue.qsize() - len(self._pool)


    def isempty(self):
        return self._taskqueue.qsize() + len(self._pool) == 0


    def kill(self, pid):
        try:
            Process_Obj, block_x, timeout_x = self._pool[pid]

            while Process_Obj.exitcode == None:
                Process_Obj.terminate()
                time.sleep(1)

            Process_Obj.join()
            del self._pool[pid]

            if block_x:
                block_x(pid, Process_Obj.exitcode)

        except Exception as o0oo0o0O00OO:
            Logging_Obj.exception(Get_lineNumber_fileName())


    def poll(self):
        for pid in self._pool.keys():
            Process_Obj, block_x, timeout_x = self._pool[pid]
            if Process_Obj.exitcode != None or timeout_x != None and time.time() > timeout_x:
                self.kill(pid)

        if len(self._pool) > self._maxtasks:
            return

        while not self._taskqueue.empty():
            oOOo0 = False
            try:
                pid, func_x, args_x, block_x, timeout_x = self._taskqueue.get(False)
                oOOo0 = True
                Process_Obj = self.PProcess(func_x, args_x)
                Process_Obj.daemon = False
                Process_Obj.start()
                self._pool[pid] = (Process_Obj, block_x, timeout_x + time.time())

            except Exception as o0oo0o0O00OO:
                Logging_Obj.exception(Get_lineNumber_fileName())
                if oOOo0:
                    self._taskqueue.put((pid,
                                         func_x,
                                         args_x,
                                         block_x,
                                         timeout_x))


    def terminate(self):

        while not self._taskqueue.empty():

            Pid, func_x, args_x, block_x, timeout_x = self._taskqueue.get(False)

            block_x(Pid, -1)

        for Pid in self._pool.keys():

            self.kill(Pid)


    def join(self):
        while not self._taskqueue.empty() or len(self._pool) > 0:
            self.poll()
            time.sleep(0.1)


class RpcError(Exception):
    def __init__(self, rpcError):
        self.error = rpcError


    def __str__(self):
        return repr(self.error)


class HttpLib(httplib.HTTPSConnection):
    def __init__(self, *args, **kwargs):
        httplib.HTTPSConnection.__init__(self, *args, **kwargs)


    def connect(self):
        Socket_Obj = socket.create_connection((self.host, self.port), self.timeout)
        if self._tunnel_host:
            self.sock = Socket_Obj
            self._tunnel()
        try:
            self.sock = ssl.wrap_socket(Socket_Obj, self.key_file, self.cert_file, ssl_version=ssl.PROTOCOL_TLSv1)
        except ssl.SSLError as III1Iiii1I11:
            self.sock = ssl.wrap_socket(Socket_Obj, self.key_file, self.cert_file, ssl_version=ssl.PROTOCOL_SSLv23)


class Loginx(object):
    def __init__(self, uhash, serviceURL, serviceName=None):
        self.__serviceURL = serviceURL
        self.__serviceName = serviceName
        self.__uhash = uhash


    def __getattr__(self, name):
        if self.__serviceName != None:
            name = '%s.%s' % (self.__serviceName, name)
        return Loginx(self.__uhash, self.__serviceURL, name)


    def __call__(self, *args):

        PC_uuid = str(uuid.uuid1())
        Login_Info_json = json.dumps({'method': self.__serviceName,
                          'params': args,
                          'uid': self.__uhash,
                          'uuid': PC_uuid})

        Mysql_table_insert('rpclog', method=self.__serviceName, params=repr(args), uid=self.__uhash, uuid=PC_uuid)

        Login_Info_json = md5.md5(Login_Info_json).hexdigest() + '|' + zlib.compress(Login_Info_json, 9)

        ServerURL = self.__serviceURL
        INT_15 = 15
        for For_int in range(INT_15):
            try:
                HTTP_getRead = None

                for For_int in range(3):

                    ServerInfo = urlparse.urlparse(ServerURL)

                    if ServerInfo.scheme == 'https':
                        Http_Obj = HttpLib(ServerInfo.hostname, ServerInfo.port, timeout=60)
                    else:
                        Http_Obj = httplib.HTTPConnection(ServerInfo.hostname, ServerInfo.port, timeout=60)

                    Http_Obj.putrequest('POST', ServerInfo.path)
                    Http_Obj.putheader('Content-Length', str(len(Login_Info_json)))
                    Http_Obj.putheader('Content-Type', 'application/json')
                    Http_Obj.endheaders()

                    Http_Obj.send(Login_Info_json)

                    HTTP_getResponse = Http_Obj.getresponse()

                    HTTP_getHeaders = dict(HTTP_getResponse.getheaders())

                    if HTTP_getHeaders.has_key('location') and HTTP_getHeaders['location'] != ServerURL:

                        Http_Obj.close()
                        ServerURL = HTTP_getHeaders['location']

                    else:

                        HTTP_getRead = HTTP_getResponse.read()
                        Http_Obj.close()
                        break

                if not HTTP_getRead:
                    raise IOError('Content empty')
                    # print HTTP_getRead

                Find_return = HTTP_getRead.find('|')
                #-------------------
                Code_md5, code_json = HTTP_getRead[:Find_return], zlib.decompress(HTTP_getRead[Find_return + 1:])

                if Code_md5 != md5.md5(code_json).hexdigest():

                    raise IOError('json decode error')

                HTTP_getResponse = json.loads(code_json)

                if PC_uuid != HTTP_getResponse['uuid']:

                    raise IOError('UUID unmatched')

            except Exception as o0oo0o0O00OO:

                if For_int == INT_15 - 1:
                    Logging_Obj.exception(Get_lineNumber_fileName())
                    raise o0oo0o0O00OO
                else:
                    time.sleep(5)
            else:
                if HTTP_getResponse['error'] != None:
                    raise RpcError(HTTP_getResponse['error'])
                else:
                    return HTTP_getResponse['result']


def addTargetModule(module='__main__'):
    global Login_Get

    StringValue = String_IO.getvalue()#获取缓存文件数据
    if Login_Get and StringValue:
        Login_Get.add_error(StringValue, module)


class Exploit_run(object):
    @staticmethod
    def _connect(*args, **kwargs):
        oO0, O0OO0O, args = args

        o00oO0oo0OO = args[0].gettimeout()
        if (o00oO0oo0OO == None or o00oO0oo0OO != 0) and oO0._speed > 0:
            while True:
                O0O0OOOOoo = time.time()
                oOooO0 = max(0.01, O0O0OOOOoo - oO0.__ts)
                if oOooO0 > 5:
                    oO0.__conn = 0
                    oO0.__ts = O0O0OOOOoo
                    break
                if oO0.__conn / oOooO0 <= oO0._speed:
                    break
                else:
                    time.sleep(0.1)

            oO0.__conn += 1

        oOOoo00O00o = oO0._dns.lookup(args[1][0])
        if not oOOoo00O00o:
            raise IOError('DNS:lookup')
        return apply(O0OO0O, args, kwargs)


    @staticmethod
    def _getaddrinfo(*args, **kwargs):
        oO0, O0OO0O, args = args
        oOOoo00O00o = oO0._dns.lookup(args[0])
        if not oOOoo00O00o:
            raise IOError('DNS:lookup')
        return apply(O0OO0O, (oOOoo00O00o,) + args[1:], kwargs)


    @staticmethod
    def _gethostbyname(self, real, hostname):
        oOOoo00O00o = self._dns.lookup(hostname)
        if not oOOoo00O00o:
            raise IOError('DNS:lookup')
        return apply(real, (oOOoo00O00o,))


    def __init__(self, tid, target, policy):

        Scan_ThreadLocal.__target = target
        Scan_ThreadLocal.__pid = 0

        self._tid = tid
        self._target = target
        self._log_filter = []
        self._db_lock = threading.RLock()
        self._id = 0

        self._G = {'target': target,
                   'subdomain': bool(policy.get('subdomain', True)),
                   'scanport': bool(policy.get('scanport', True)),
                   'disallow_ip': ['127.0.0.1'],
                   'disallow_url': policy.get('disallow', '').split(';'),
                   'kv': {},
                   'user_dict': policy.get('user_dict'),
                   'pass_dict': policy.get('pass_dict')}

        util._G = self._G
        try:
            mainHost, mainHost, C_ip = socket.gethostbyname_ex('wildcardfake.' + target)
            self._G['disallow_ip'] += C_ip    #限制扫描C段
        except:
            pass

        self._max_task   = int(policy.get('maxtask', 10240))
        self._speed      = int(policy.get('speed', 20))
        self._user_agent = policy.get('useragent', '')
        self._cookie     = policy.get('cookie', '')

        self._sniff_plugins = {}
        self._plugins = {}
        self._modules = {}

        for plugin_x in policy['plugins']:
            try:
                Plugin = policy['plugins'][plugin_x]

                OO0OoOO0o0o = 0
                if imp.get_magic() == Plugin[:4]:
                    oo = marshal.loads(Plugin[8:])
                    OO0OoOO0o0o = struct.unpack('<l', Plugin[4:8])[0]

                else:
                    oo = Plugin
                II = self._load_module(oo)

                o00oo0 = None
                if OO0OoOO0o0o > 1440345600:
                    o00oo0 = Plugin[-48:-16]
                    I11ii1IIiIi = Plugin[-16:]
                    if I11ii1IIiIi != md5.new(Plugin[:-16]).digest()[::-1]:
                        Logging_Obj.exception('[_load_module_hash_not_match:%s]' % plugin_x)
                        continue

                self._patch_module(II, o00oo0)
                if II.audit.func_code.co_argcount == 3:
                    self._sniff_plugins[plugin_x] = II
                else:
                    self._modules[plugin_x] = II
                    self._plugins[plugin_x] = Plugin
            except:
                Logging_Obj.exception('[_load_module_:%s]' % plugin_x)

        self._dns = DNS.DNSCache()

        Socket_connect = socket.socket.connect
        Socket_connect_ex = socket.socket.connect_ex

        oooO = socket.getaddrinfo

        Socket_gethostbyname = socket.gethostbyname

        ooo = socket.gethostbyname_ex

        socket.socket.connect = lambda *args, **kwargs: apply(self._connect,
                                                              (self, Socket_connect) + (args,),
                                                              kwargs)

        socket.socket.connect_ex = lambda *args, **kwargs: apply(self._connect,
                                                                 (self, Socket_connect_ex) + (args,),
                                                                 kwargs)

        socket.getaddrinfo = lambda *args, **kwargs: apply(self._getaddrinfo,
                                                           (self, oooO) + (args,),
                                                           kwargs)


        socket.gethostbyname = lambda Ooo0oOooo0: apply(self._gethostbyname, (self, Socket_gethostbyname, Ooo0oOooo0))

        socket.gethostbyname_ex = lambda Ooo0oOooo0: apply(self._gethostbyname, (self, ooo, Ooo0oOooo0))

        self.__conn = 0
        self.__ts = time.time()

        self._task_count = 0
        self._db_uuid = []
        self._db_task_handled = {}
        self._db_task_queue = Queue.PriorityQueue()


    def _load_module(self, chunk, name='<memory>'):
        II = imp.new_module(str(name))
        exec chunk in II.__dict__
        return II


    def _problem(self, level, body, uuid):
        oo00O00oO = Scan_ThreadLocal.__target
        oooooOoo0ooo = int(Scan_ThreadLocal.__pid)
        if body and not isinstance(body, unicode):
            try:
                body = body.decode('utf-8', 'ignore')
            except UnicodeDecodeError:
                body = repr(body)

        if not oo00O00oO:
            oo00O00oO = self._target

        uuid = md5.md5(oo00O00oO + ':' + str(uuid or repr(body))).hexdigest()

        if uuid in self._log_filter:
            return

        self._log_filter.append(uuid)
        try:
            Login_Get.add_log(self._tid, level, oo00O00oO, oooooOoo0ooo, body)
        except:
            Logging_Obj.exception('_problem TID:%d Level:%d Target:%s PID:%d Body:%s' % (self._tid,
                                                                                         level,
                                                                                         repr(oo00O00oO),
                                                                                         oooooOoo0ooo,
                                                                                         repr(body)))


    def _security_note(self, body, uuid=None):
        return self._problem(o00ooooO0oO, body, uuid)

    def _security_info(self, body, uuid=None):
        return self._problem(oOoOo00oOo, body, uuid)

    def _security_warning(self, body, uuid=None):
        return self._problem(Oo, body, uuid)

    def _security_hole(self, body, uuid=None):
        return self._problem(o00O00O0O0O, body, uuid)

    def task_push(self, service, arg, uuid=None, target=None, pr=-1):

        if target is None:
            target = Scan_ThreadLocal.__target

        if self._max_task != 0 and self._task_count > self._max_task:
            return False

        uuid = md5.md5(target + ':' + service + ':' + str(uuid or repr(arg))).hexdigest()

        self._db_lock.acquire()
        if uuid not in self._db_uuid:
            self._db_uuid.append(uuid)
            self._id += 1

        else:
            self._db_lock.release()
            return False

        self._db_lock.release()

        Mysql_table_insert('tasklog', uuid=uuid, plugin_id=Scan_ThreadLocal.__pid, service=service, arg=repr(arg),
                           target=target,
                           pr=pr, ididid=self._id)

        for OO0O0 in self._modules:

            i1OOO0000oO = None
            iI1i111I1Ii = time.time() * 1000

            try:
                i1OOO0000oO = self._modules[OO0O0].assign(service, arg)
            except:
                Logging_Obj.exception('[M:%d] %s' % (OO0O0, repr(arg)))

            i11i1ii1I = time.time() * 1000

            if not isinstance(i1OOO0000oO, tuple):
                Mysql_table_insert('assignlog', time=int(i11i1ii1I - iI1i111I1Ii), uuid='', plugin_id=OO0O0,
                                   service=service,
                                   prearg=repr(arg), arg='', isret=0, push=0)
                continue

            I11I11 = self._plugins[OO0O0]

            III1Iiii1I11, o00o0, uuid = i1OOO0000oO if len(i1OOO0000oO) == 3 else i1OOO0000oO + (None,)
            iIiIIIi = o00o0 if isinstance(o00o0, list) else [o00o0]

            self._db_lock.acquire()

            try:
                O0O0Oo00 = 0

                for oOoO00o in iIiIIIi:

                    hash = md5.md5(str(OO0O0) + ':' + repr(oOoO00o)).hexdigest()

                    if hash not in self._db_task_handled:

                        self._db_task_handled[hash] = 1

                        self._db_task_queue.put((pr,
                                                 OO0O0,
                                                 oOoO00o,
                                                 target,
                                                 hash))
                        self._task_count += 1
                        O0O0Oo00 = 1

                    else:

                        O0O0Oo00 = 0

                    Mysql_table_insert('assignlog', time=int(i11i1ii1I - iI1i111I1Ii), uuid=hash, plugin_id=OO0O0,
                                       service=service,
                                       prearg=repr(arg), arg=repr(oOoO00o), isret=1, push=O0O0Oo00, i=ai + 1)

            except Exception as o0oo0o0O00OO:
                pass

            self._db_lock.release()


    def _audit_sniff(self, url, head, data):
        __opid = Scan_ThreadLocal.__pid

        for OO0O0 in self._sniff_plugins:

            Day_time_1 = time.time() * 1000
            try:

                Scan_ThreadLocal.__pid = OO0O0

                self._sniff_plugins[OO0O0].audit(url, head, data)

            except:
                Logging_Obj.exception('[M:%d] %s' % (OO0O0, repr(url)))

            Day_time_2 = time.time() * 1000

            Mysql_table_insert('auditlog', uuid=md5.md5(url).hexdigest(), plugin_id=OO0O0, type=1, arg=repr(url),
                               time=int(Day_time_2 - Day_time_1))

        Scan_ThreadLocal.__pid = __opid

    def _debug(self, fmt, *args):
        Print_str(fmt, *args)
        Mysql_table_insert('debuglog', plugin_id=Scan_ThreadLocal.__pid, body=fmt % args)


    def _patch_module(self, m, key=None):
        m.util = util
        m.threadpool = threadpool
        m._G = self._G
        m.debug = self._debug
        m.log = Mysql_table_insert
        m.audit_sniff = self._audit_sniff
        m.task_push = self.task_push
        m.security_note = self._security_note
        m.security_info = self._security_info
        m.security_warning = self._security_warning
        m.security_hole = self._security_hole
        if key:
            m.decode = decode.Decoder(key).decode


    def worker(self, args):
        PID, IP_1, Target_IP, Target_Hash = args

        Scan_ThreadLocal.__target = Target_IP
        Scan_ThreadLocal.__pid = PID

        Tmp_INT = 0
        KEY_Patch_Module = None
        PluginPID = self._plugins[PID]

        if imp.get_magic() == PluginPID[:4]:
            Data_xuliehua = marshal.loads(PluginPID[8:]) #读序列化数据
            Tmp_INT = struct.unpack('<l', PluginPID[4:8])[0] #将二进制数据转换成 Python 数据
        else:
            Data_xuliehua = PluginPID
        II = self._load_module(Data_xuliehua)

        if Tmp_INT > 1440345600:

            KEY_Patch_Module = PluginPID[-48:-16]
            module_Hash = PluginPID[-16:]

            if module_Hash != md5.new(PluginPID[:-16]).digest()[::-1]:
                Logging_Obj.exception('[_load_module_hash_not_match:%s]' % PID)#载入模块的Hash不匹配
                return

        II.curl = miniCurl.Curl(sniff_func=self._audit_sniff, init_cookie=self._cookie, user_agent=self._user_agent,
                                plugin_id=PID, log_func=Mysql_table_insert)
        self._patch_module(II, KEY_Patch_Module)

        Day_time_1 = time.time() * 1000

        try:
            II.audit(IP_1)
        except:
            Logging_Obj.exception('[M:%s] %s' % (PID, repr(IP_1)))

        Day_time_2 = time.time() * 1000

        Mysql_table_insert('auditlog', uuid=Target_Hash, plugin_id=PID, type=0, arg=repr(IP_1),
                           time=int(Day_time_2 - Day_time_1))


    def run(self):
        Thread_Pool_Obj = threadpool.ThreadPool(30)
        I1i11111i1i11 = 0
        OOoOOO0 = 0.0
        I1I1i = time.time()
        while True:
            I1IIIiIiIi = Thread_Pool_Obj.busy()

            if self._task_count and time.time() - I1I1i > 15:
                I1I1i = time.time()
                iIi1i1iIi1iI = 100 * float(I1i11111i1i11 - I1IIIiIiIi) / self._task_count
                if iIi1i1iIi1iI != OOoOOO0:
                    OOoOOO0 = iIi1i1iIi1iI
                    Login_Get.set_task_progress(self._tid, iIi1i1iIi1iI)

            if self._db_task_queue.qsize():
                for OOoO00 in range(min(Thread_Pool_Obj.idel(), self._db_task_queue.qsize())):
                    IiIii1i111 = 0
                    try:
                        iIo0o00, OO0O0, oOoO00o, oo00O00oO, hash = self._db_task_queue.get_nowait()
                        IiIii1i111 = 1
                    except Exception as o0oo0o0O00OO:
                        continue

                    if IiIii1i111 == 0:
                        break
                    Thread_Pool_Obj.push(self.worker, (OO0O0,
                                                       oOoO00o,
                                                       oo00O00oO,
                                                       hash))
                    I1i11111i1i11 += 1

            elif I1IIIiIiIi == 0:
                break
            Thread_Pool_Obj.wait_for_idel(5)

        Thread_Pool_Obj.wait()


def Target_isOK(target):
    for i in target:
        i = ord(i) #参数是一个ascii字符，返回值是对应的十进制整数

        if (i > 57 or i < 48) and i != 46:
            return False

    return True


def ProcessWork(glock, gdebug, debugkey, uhash, rpc_server, tid, target, Plugins_list):
    global Debug_yes_no
    global sys_debug_yes_no
    global Login_Get
    global debug_key
    global Multiprocessing_RLock

    Multiprocessing_RLock = glock

    sys_debug_yes_no = gdebug
    debug_key = debugkey
    Debug_yes_no = True

    Loginx_Obj = Loginx(uhash, rpc_server)

    Oo000ooOOO = None

    if Debug_X(debugkey):

        thread.start_new_thread(Mysql_insert_QueueInfo, ())

    try:

        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        signal.signal(signal.SIGINT, signal.SIG_DFL)

        Loginx_Obj.set_task_status(tid, Range_3)

        Exploit_run_Obj = Exploit_run(tid, target, Plugins_list)

        if 'entry' in Plugins_list:

            if Plugins_list['entry'].startswith('http'):#  String.startswith('xxx')判断开头是否是xxx

                Exploit_run_Obj.task_push('www', str(Plugins_list['entry']))
            else:

                Exploit_run_Obj.task_push('www', 'http://%s%s' % (target, Plugins_list['entry']))

        if not Target_isOK(target):

            Exploit_run_Obj.task_push('dns', target) # task_push(self, service, arg, uuid=None, target=None, pr=-1):

        Exploit_run_Obj.task_push('www', 'http://%s/' % target)

        Exploit_run_Obj.run()

    except (KeyboardInterrupt, SystemExit):

        pass

    except Exception as o0oo0o0O00OO:

        Logging_Obj.exception('ProcessWorker:<%d %s>' % (tid, target))

    finally:

        Loginx_Obj.set_task_status(tid, Range_5)

        if Mysql_Obj:
            Mysql_table_insert('loglog', body='exit')

    addTargetModule(target)


def Set_task_status(tid, exitcode):
    INT_5 = Range_5
    if exitcode != signal.SIG_DFL:
        INT_5 = Range_6
    Login_Get.set_task_status(tid, INT_5)#启动任务


Multiprocessing_Event = threading.Event()


def Multi_Event_Set(signum, frame):#多进程同步设置
    Multiprocessing_Event.set()


def Multi_Event_Kill(s):
    for ii in range(0, s * 1000, 100):
        if Multiprocessing_Event.is_set():
            raise SystemExit('Killed')
        try:
            time.sleep(0.1)
        except:
            pass


def txt_wrap_by(start_str, end_str, html):
    start = html.find(start_str)
    if start >= 0:
        start += len(start_str)
        end = html.find(end_str, start)
        if end >= 0:
            print html[start:end].strip()
            return html[start:end].strip()


def Mainx():
    global Argv_5
    global Login_Get
    global _C
    global _U
    global _S
    global _B

    signal.signal(signal.SIGTERM, Multi_Event_Set)
    signal.signal(signal.SIGINT, Multi_Event_Set)

    debugkey_str = ''

    if len(sys.argv) >= 3 and sys.argv[1] == '-m':
        Argv_5 = int(sys.argv[2])

        if len(sys.argv) >= 4:
            debugkey_str = sys.argv[3]

    if Debug_X(debugkey_str, 'main'):
        print 'tid=', thread.start_new_thread(Mysql_insert_QueueInfo, ())

    if '_S' not in globals():
        _S = 'https'
    if '_U' not in globals():
        _U = '我操你妈'
    if '_B' not in globals():
        _B = 'www.bugscan.net'

    Urls = '%s://%s/rpcs' % (_S, _B)
    Login_Get = Loginx(_U, Urls)
    VER_INT = 1.95
    UPdate_yes_no = False
    Plugin_Code = {}
    Scan_thread_obj = SCAN_multiprocessing(Argv_5)
    Scan_thread_idel = Scan_thread_obj.idel()
    while True:
        SID_INT = None
        ju_INT_15 = 15
        Print_str('[***] Initialize user <%s@%s> Debug: %s', _U, _S, bool(sys.flags.debug))
        Print_str('[***] Max: [%d], PID: %d, DNS Server: %s', Argv_5, os.getpid(), repr(DNS._DNSSERVERS))
        try:

            while True:

                if SID_INT is None:
                    SID_INT = Login_Get.login(platform.system(), str(VER_INT))
                    Print_str('[!!!] Core Version ' + str(VER_INT))

                    if not SID_INT:

                        Print_str('[!!!] Login Error, plz check your arguments')
                        Multi_Event_Kill(ju_INT_15)

                        continue
                    else:
                        Print_str('[+++] Login OK! SID=%d', SID_INT)
                else:

                    Scan_thread_obj.poll()
                    Multi_Event_Kill(ju_INT_15)

                if Scan_thread_idel == -1:
                    Scan_thread_idel = 0
                else:
                    Scan_thread_idel = Scan_thread_obj.idel()
                Task_List = Login_Get.get_task_list(SID_INT, Scan_thread_idel)#获取任务列表

                if not Task_List:
                    continue

                Node_Ver = Task_List.get('nodever')

                if Node_Ver and float(Node_Ver) > VER_INT:

                    Scan_thread_idel = -1

                    if Scan_thread_obj.isempty():

                        Print_str('[!!!] Update New Core ,Version: %s->%s' % (str(VER_INT), str(Node_Ver)))
                        UPdate_yes_no = True

                        break

                for Tasks_n in Task_List['tasks']:
                    tasksID = int(Tasks_n['id'])

                    targer = Tasks_n['target'].encode('utf-8').strip()

                    Plugins_list = json.loads(base64.decodestring(Tasks_n['policy']))#插件列表

                    pluginTimeOUT = 259200

                    Print_str('[***] Dispatch %s', targer)

                    if 'timeout' in Plugins_list:
                        pluginTimeOUT = int(Plugins_list['timeout']) * 60 * 60

                    Plugin_Hash_List = []

                    for hash in Plugins_list['plugins']:

                        if hash not in Plugin_Code:
                            Plugin_Hash_List.append(hash)

                    if Plugin_Hash_List:

                        Print_str('[***] fetch %d new plugins', len(Plugin_Hash_List))

                        hashANDpycode_List = Login_Get.get_plugin_list(Plugin_Hash_List)
                        print hashANDpycode_List

                        for hash in hashANDpycode_List:

                            idANDpycode = hashANDpycode_List[hash]
                            Plugin_Code[hash] = (idANDpycode[0], zlib.decompress(binascii.a2b_hex(idANDpycode[1])))

                            if True:#获取插件部分
                                if str(Plugin_Code[hash][1]).find('def ') > -1:
                                    print txt_wrap_by("if service",":",str(Plugin_Code[hash][1])).replace('"',"").replace("'","").replace("=","").replace(" ","")+".py"
                                else:
                                    print binascii.b2a_hex(Plugin_Code[hash][1])

                    plugins = {}
                    for hash in Plugins_list['plugins']:
                        if hash in Plugin_Code:
                            Hash_id, pycode = Plugin_Code[hash]
                            plugins[Hash_id] = pycode

                    Plugins_list['plugins'] = plugins

                    NO_SCAN_SITE = ['wicwuzhen.cn', 'zjol.com.cn']
                    YES_SCAN_NO = False

                    for NO_SCAN_X in NO_SCAN_SITE:
                        if NO_SCAN_X in targer:
                            YES_SCAN_NO = True
                            break

                    if not YES_SCAN_NO:
                        Scan_thread_obj.push(tasksID, ProcessWork,
                            (Multiprocessing_RLock, sys.flags.debug, debugkey_str, _U, Urls,tasksID, targer,Plugins_list),
                                             Set_task_status, pluginTimeOUT)
                    else:
                        Login_Get.set_task_status(tasksID, Range_5)

                oO0o00oOOooO0 = 0
                for tasksID in Task_List['stops']:
                    tasksID = int(tasksID)
                    Scan_thread_obj.kill(tasksID)

                    Print_str('[+++] Stop task TID: %d/%d', tasksID, oO0o00oOOooO0)

                    oO0o00oOOooO0 += 1

        except (KeyboardInterrupt, SystemExit):
            Print_str('[***] KeyboardInterrupt')
            _C = False
            break
        except Exception as o0oo0o0O00OO:
            Logging_Obj.exception(Get_lineNumber_fileName())
            Multi_Event_Kill(ju_INT_15)
        finally:
            addTargetModule()
            if SID_INT:
                Print_str('[***] Logout')
                Login_Get.logout(SID_INT)
            if Mysql_Obj:
                Mysql_table_insert('loglog', body='exit')

        if UPdate_yes_no:
            break

    Scan_thread_obj.terminate()


if __name__ == '__fork__':
    apply(globals()[__func__], __args__)
elif __name__ == '__main__':
    Mainx()

