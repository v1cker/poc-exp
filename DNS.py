
__version__ = '0.5'
import random
import select
import socket
import string
import struct
import types
import sys
import re
import os
import time
import threading
_EnableDebug = False
T_UNKNOWN = 0
T_A = 1
T_NS = 2
T_MD = 3
T_MF = 4
T_CNAME = 5
T_SOA = 6
T_MB = 7
T_MG = 8
T_MR = 9
T_NULL = 10
T_WKS = 11
T_PTR = 12
T_HINFO = 13
T_MINFO = 14
T_MX = 15
T_TXT = 16
T_RP = 17
T_AFSDB = 18
T_X25 = 19
T_ISDN = 20
T_RT = 21
T_PX = 26
T_GPOS = 27
T_AAAA = 28
T_LOC = 29
T_SRV = 33
T_NAPTR = 35
T_KX = 36
T_APL = 42
T_IXFR = 251
T_AXFR = 252
T_MAILB = 253
T_MAILA = 254
T_ANY = 255
DNS_TYPE = {T_UNKNOWN: 'UNKNOWN',
 T_A: 'A',
 T_NS: 'NS',
 T_MD: 'MD',
 T_MF: 'MF',
 T_CNAME: 'CNAME',
 T_SOA: 'SOA',
 T_MB: 'MB',
 T_MG: 'MG',
 T_MR: 'MR',
 T_NULL: 'NULL',
 T_WKS: 'WKS',
 T_PTR: 'PTR',
 T_HINFO: 'HINFO',
 T_MINFO: 'MINFO',
 T_MX: 'MX',
 T_TXT: 'TXT',
 T_RP: 'RP',
 T_AFSDB: 'AFSDB',
 T_X25: 'X25',
 T_ISDN: 'ISDN',
 T_RT: 'RT',
 T_PX: 'PX',
 T_GPOS: 'GPOS',
 T_AAAA: 'AAAA',
 T_LOC: 'LOC',
 T_SRV: 'SRV',
 T_NAPTR: 'NAPTR',
 T_KX: 'KX',
 T_APL: 'APL',
 T_IXFR: 'IXFR',
 T_AXFR: 'AXFR',
 T_MAILB: 'MAILB',
 T_MAILA: 'MAILA',
 T_ANY: 'ANY'}
C_RSV = 0
C_IN = 1
C_CS = 2
C_CH = 3
C_HS = 4
C_NONE = 254
C_ANY = 255
DNS_CLASS = {C_RSV: 'RESERVED',
 C_IN: 'IN',
 C_CS: 'CS',
 C_CH: 'CH',
 C_HS: 'HS',
 C_NONE: 'NONE',
 C_ANY: 'ANY'}
_HDR_REQUEST = 0
_HDR_RESPONSE = 32768
_HDR_OPCODE_MASK = 30720
_HDR_OPCODE_QUERY = 0
_HDR_OPCODE_IQUERY = 2048
_HDR_OPCODE_STATUS = 4096
_HDR_OPCODE_RSV = 6144
_HDR_OPCODE_NOTIFY = 8192
_HDR_OPCODE_UPDATE = 10240
_HDR_AUTH_ANSWER = 1024
_HDR_TRUNCATION = 512
_HDR_REC_DESIRED = 256
_HDR_REC_AVAIL = 128
_HDR_RESERVED_MASK = 112
_HDR_RCODE_MASK = 15
HDR_RCODE_NOERROR = 0
HDR_RCODE_FORMERR = 1
HDR_RCODE_SERVFAIL = 2
HDR_RCODE_NXDOMAIN = 3
HDR_RCODE_NOTIMP = 4
HDR_RCODE_REFUSED = 5
HDR_RCODE_YXDOMAIN = 6
HDR_RCODE_YXRRSET = 7
HDR_RCODE_NXRRSET = 8
HDR_RCODE_NOTAUTH = 9
HDR_RCODE_NOTZONE = 10
HDR_RCODE = {HDR_RCODE_NOERROR: ['Success', 'No error codition'],
 HDR_RCODE_FORMERR: ['Format Error', 'Format Error - The name server was unable to interpret the query.'],
 HDR_RCODE_SERVFAIL: ['Server Failure', 'Server failure - The name server was unable to process this query due to a problem with the name server'],
 HDR_RCODE_NXDOMAIN: ['Non-Existent Domain', 'Name Error - Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist.'],
 HDR_RCODE_NOTIMP: ['Not Implemented', 'Not Implemented - The name server does not support the requested kind of query.'],
 HDR_RCODE_REFUSED: ['Refused', 'Refused - The name server refuses to perform the specified operation for policy reasons.'],
 HDR_RCODE_YXDOMAIN: ['Name Exists when it should not', 'Some name that ought not to exist, does exist.'],
 HDR_RCODE_YXRRSET: ['RR Set Exists when it should not', 'Some RRset that ought not to exist, does exist.'],
 HDR_RCODE_NXRRSET: ['RR Set that should exist does not', 'Some RRset that ought to exist, does not exist.'],
 HDR_RCODE_NOTAUTH: ['Server Not Authoritative for zone', 'The server is not authoritative for the zone named in the Zone Section.'],
 HDR_RCODE_NOTZONE: ['Name not contained in zone', 'A name used in the Prerequisite or Update Section is not within the zone denoted by the Zone Section.']}

def binipdisplay(s):
    """convert a binary array of ip adresses to a python list"""
    if len(s) % 4 != 0:
        raise EnvironmentError
    ol = []
    for i in range(len(s) / 4):
        s1 = s[:4]
        s = s[4:]
        ip = []
        for j in s1:
            ip.append(str(ord(j)))

        ol.append('.'.join(ip))

    return ol


def stringdisplay(s):
    """convert "d.d.d.d,d.d.d.d" to ["d.d.d.d","d.d.d.d"].
       also handle u'd.d.d.d d.d.d.d', as reporting on SF
    """
    import re
    return [ str(x) for x in re.split('[ ,]', s) ]


def RegistryResolve():
    import re
    import _winreg
    nameservers = []
    x = _winreg.ConnectRegistry(None, _winreg.HKEY_LOCAL_MACHINE)
    try:
        y = _winreg.OpenKey(x, 'SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters')
    except EnvironmentError:
        try:
            y = _winreg.OpenKey(x, 'SYSTEM\\CurrentControlSet\\Services\\VxD\\MSTCP')
            nameserver, dummytype = _winreg.QueryValueEx(y, 'NameServer')
            if nameserver and nameserver not in nameservers:
                nameservers.extend(stringdisplay(nameserver))
        except EnvironmentError:
            pass

        return nameservers

    try:
        nameserver = _winreg.QueryValueEx(y, 'DhcpNameServer')[0].split()
    except:
        nameserver = _winreg.QueryValueEx(y, 'NameServer')[0].split()

    if nameserver:
        nameservers = nameserver
    nameserver = _winreg.QueryValueEx(y, 'NameServer')[0]
    _winreg.CloseKey(y)
    try:
        y = _winreg.OpenKey(x, 'SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\DNSRegisteredAdapters')
        for i in range(1000):
            try:
                n = _winreg.EnumKey(y, i)
                z = _winreg.OpenKey(y, n)
                dnscount, dnscounttype = _winreg.QueryValueEx(z, 'DNSServerAddressCount')
                dnsvalues, dnsvaluestype = _winreg.QueryValueEx(z, 'DNSServerAddresses')
                nameservers.extend(binipdisplay(dnsvalues))
                _winreg.CloseKey(z)
            except EnvironmentError:
                break

        _winreg.CloseKey(y)
    except EnvironmentError:
        pass

    try:
        y = _winreg.OpenKey(x, 'SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces')
        for i in range(1000):
            try:
                n = _winreg.EnumKey(y, i)
                z = _winreg.OpenKey(y, n)
                try:
                    nameserver, dummytype = _winreg.QueryValueEx(z, 'NameServer')
                    if nameserver and nameserver not in nameservers:
                        nameservers.extend(stringdisplay(nameserver))
                except EnvironmentError:
                    pass

                _winreg.CloseKey(z)
            except EnvironmentError:
                break

        _winreg.CloseKey(y)
    except EnvironmentError:
        pass

    _winreg.CloseKey(x)
    return nameservers


def _import_dnsservers():
    servers = []
    if sys.platform in ('win32', 'nt'):
        servers = RegistryResolve()
    else:
        try:
            lines = open('/etc/resolv.conf').readlines()
            for line in lines:
                line = line.strip()
                if not line or line[0] == ';' or line[0] == '#':
                    continue
                fields = line.split()
                if len(fields) < 2:
                    continue
                if fields[0] == 'nameserver':
                    servers.append(fields[1])

        except:
            pass

    if len(servers) == 0:
        servers.append('114.114.114.114')
        servers.append('8.8.8.8')
    return servers


_DNSSERVERS = _import_dnsservers()

def _unique(lst):
    res = []
    for elem in lst:
        if elem not in res:
            res.append(elem)

    return res


class _debug():

    def __init__(self, name):
        self._name = name
        if _EnableDebug:
            print '%s.py: %s <<' % (__name__, self._name)

    def msg(self, message):
        if _EnableDebug:
            print '%s.py: %s: %s' % (__name__, self._name, message)

    def __del__(self):
        if _EnableDebug:
            print '%s.py: %s >>' % (__name__, self._name)


class QueryError(Exception):
    """
    Exception raised during DNS query compilation
    """
    pass


class AnswerError(Exception):
    """
    Exception raised during DNS answer parsing
    """
    pass


class IncompleteAnswerError(AnswerError):
    """
    Exception raised if DNS answer is incomplete
    """
    pass


class ResolverError(Exception):
    """
    Exception raised during DNS resolution
    """
    pass


class ConnectionError(ResolverError):
    """
    Exception raised when communicating with name server
    """
    pass


class ServerError(ResolverError):
    """
    Exception raised by non-zero RCODE field
    """
    pass


_QRY_NAME = 0
_QRY_TYPE = 1
_QRY_CLASS = 2

class _dnsquery():

    def __init__(self, query, sections = None, recursion = False, id = None):
        dbg = _debug('_dnsquery::__init__')
        self._query = ()
        self._sections = {'AUTHORITY': [],
         'ADDITIONAL': []}
        self.__sanity(query, sections)
        self._recursion = recursion
        self._id = id or self.__getID()
        dbg.msg('%u: %s' % (self._id, self._query))

    def __sanity(self, query, sections):
        dbg = _debug('_dnsquery::__sanity')
        addr, qtype, qclass = query
        if not isinstance(addr, types.StringTypes):
            raise ValueError('Invalid name %s' % str(addr))
        if qtype == 0 or not DNS_TYPE.has_key(qtype):
            raise ValueError('Invalid type %u' % qtype)
        if qclass == 0 or not DNS_CLASS.has_key(qclass):
            raise ValueError('Invalid class %u' % qclass)
        self._query = query
        if not sections:
            return
        sections = self.__normalize(sections)
        for k in ['AUTHORITY', 'ADDITIONAL']:
            if sections.has_key(k):
                v = sections[k]
                if not (isinstance(v, types.ListType) or isinstance(v, types.TupleType)):
                    raise ValueError('%s format error' % k)
                self._sections[k] = v

    def __normalize(self, the_map):
        dbg = _debug('_dnsquery::__normalize')
        res = {}
        for key in the_map:
            if isinstance(key, types.StringTypes):
                res[key.upper()] = the_map[key]

        return res

    def __pack16(self, value):
        dbg = _debug('_dnsquery::__pack16')
        return struct.pack('>H', value)

    def __pack32(self, value):
        dbg = _debug('_dnsquery::__pack32')
        return struct.pack('>L', value)

    def __getID(self):
        dbg = _debug('_dnsquery::__getID')
        return random.randrange(1, 65535)

    def __mkqhead(self):
        dbg = _debug('_dnsquery::__mkqhead')
        qhead = self.__pack16(self._id)
        r = _HDR_REQUEST + _HDR_OPCODE_QUERY
        if self._recursion:
            r += _HDR_REC_DESIRED
        qhead += self.__pack16(r)
        qhead += self.__pack16(1)
        qhead += self.__pack16(0)
        qhead += self.__pack16(len(self._sections['AUTHORITY']))
        qhead += self.__pack16(len(self._sections['ADDITIONAL']))
        return qhead

    def __mkqname(self, req):
        dbg = _debug('_dnsquery::__mkqname')
        res = ''
        tokens = req.split('.')
        for token in tokens:
            res += '%c' % len(token) + token

        return res + '\x00'

    def __arpadomain(self, ipaddress):
        dbg = _debug('_dnsquery::__arpadomain(%s)' % ipaddress)
        addrlist = ipaddress.split('.')
        if len(addrlist) != 4 or not self.__isipaddress(addrlist):
            return ipaddress
        addrlist.reverse()
        addrlist.append('in-addr')
        addrlist.append('arpa')
        return string.join(addrlist, '.')

    def __isipaddress(self, ipaddrlist):
        for i in ipaddrlist:
            try:
                ipaddrblock = int(i)
            except:
                return False

            if ipaddrblock != ipaddrblock & 255:
                return False

        return True

    def __SOA_RDATA(self, data):
        dbg = _debug('_dnsquery::__SOA_RDATA')
        rdata = ''
        for name in ['MNAME', 'RNAME']:
            rdata += self.__mkqname(name)

        rdata += self.__pack32(data['SERIAL'])
        for key in ['REFRESH',
         'RETRY',
         'EXPIRE',
         'MINIMUM']:
            if data.has_key(key):
                rdata += self.__pack32(data[key])
            else:
                rdata += self.__pack32(0L)

        return rdata

    def __mkqrdata(self, qtype, qclass, qrdata):
        dbg = _debug('_dnsquery::__mkqrdata')
        rdata = ''
        if qtype == T_SOA:
            rdata = self.__SOA_RDATA(qrdata)
        else:
            raise QueryError('Unsupported TYPE %u' % qtype)
        return rdata

    def __mkqsection(self, sname):
        dbg = _debug('_dnsquery::__mkqsection')
        if not self._sections.has_key(sname):
            return ''
        sqry = ''
        for section in self._sections[sname]:
            qname = section['NAME']
            qtype = section['TYPE']
            qclass = section['CLASS']
            qttl = 0L
            if section.has_key('TTL'):
                qttl = section['TTL']
            if qtype == T_PTR:
                qname = self.__arpadomain(qname)
            sqry += self.__mkqname(qname)
            sqry += self.__pack16(qtype)
            sqry += self.__pack16(qclass)
            sqry += self.__pack32(qttl)
            rdata = self.__mkqrdata(qtype, qclass, section['RDATA'])
            sqry += self.__pack16(len(rdata))
            sqry += rdata

        return sqry

    def get(self, prefix = False):
        dbg = _debug('_dnsquery::get')
        qry = self.__mkqhead()
        qname = self._query[_QRY_NAME]
        if self._query[_QRY_TYPE] == T_PTR:
            qname = self.__arpadomain(qname)
        dbg.msg('QNAME: %s' % qname)
        qry += self.__mkqname(qname)
        qry += self.__pack16(self._query[_QRY_TYPE])
        qry += self.__pack16(self._query[_QRY_CLASS])
        qry += self.__mkqsection('AUTHORITY')
        qry += self.__mkqsection('ADDITIONAL')
        if prefix:
            qry = self.__pack16(len(qry)) + qry
        return qry

    def id(self):
        return self._id

    def __str__(self):
        res = 'ID: %u\n' % self._id
        res += 'Query: %s\n' % self._query[_QRY_NAME]
        res += 'Type : %s\n' % DNS_TYPE[self._query[_QRY_TYPE]]
        res += 'Class: %s\n' % DNS_CLASS[self._query[_QRY_CLASS]]
        return res


_PARSE_SECTION = 0
_PARSE_OFFSET = 1
_PARSE_HEADER = 0
_PARSE_QUERY = 1
_PARSE_ANSWER = 2
_PARSE_AUTHORITY = 3
_PARSE_ADDITIONAL = 4
_PARSE_END = 5

class _dnsanswer():

    def __init__(self, answer = None, prefix = False):
        dbg = _debug('_dnsanswer::__init__')
        self._answer = ''
        self._prefix = prefix
        self._size = 0
        self._dict = {}
        self._complete = False
        self._status = [_PARSE_HEADER, 0]
        if answer:
            self.add(answer)

    def __parse(self):
        dbg = _debug('_dnsanswer::__parse')
        try:
            self.__parseheader()
            self.__parsequery()
            self.__parsesections()
            if self._prefix and self._size != self._status[_PARSE_OFFSET]:
                raise IncompleteAnswerError()
            self._complete = True
        except IncompleteAnswerError:
            pass

    def __parseheader(self):
        dbg = _debug('_dnsanswer::__parseheader')
        if self._status[_PARSE_SECTION] > _PARSE_HEADER:
            dbg.msg('HEADER already parsed')
            return
        assert self._status[_PARSE_OFFSET] == 0, 'Inconsistent parse offset when parsing HEADER: %u' % self._status[_PARSE_OFFSET]
        self.__sentry(len(self._answer), 12)
        self._dict['HEADER'] = {}
        self._dict['HEADER']['ID'] = self.__unpack16(self._answer[0:2])
        self._dict['HEADER']['OPCODES'] = self.__opcodes(self._answer[2:4])
        offset = 4
        for i in ('QDCOUNT', 'ANCOUNT', 'NSCOUNT', 'ARCOUNT'):
            self._dict['HEADER'][i] = self.__unpack16(self._answer[offset:offset + 2])
            offset += 2

        self._status[_PARSE_SECTION] += 1
        self._status[_PARSE_OFFSET] = offset
        dbg.msg('HEADER: %s' % self._dict['HEADER'])

    def __parsequery(self):
        dbg = _debug('_dnsanswer::__parsequery')
        if self._status[_PARSE_SECTION] > _PARSE_QUERY:
            dbg.msg('QUERY already parsed')
            return
        assert self._status[_PARSE_SECTION] == _PARSE_QUERY, 'Inconsistent parse section when parsing QUERY: %u' % self._status[_PARSE_SECTION]
        assert self._status[_PARSE_OFFSET] == 12, 'Inconsistent parse offset when parsing QUERY: %u' % self._status[_PARSE_OFFSET]
        offset = self._status[_PARSE_OFFSET]
        self._dict['QUERY'] = []
        for i in range(self._dict['HEADER']['QDCOUNT']):
            q, offset = self.__question(self._answer, offset)
            self._dict['QUERY'].append(q)

        self._status[_PARSE_SECTION] += 1
        self._status[_PARSE_OFFSET] = offset

    def __parsesections(self):
        dbg = _debug('_dnsanswer::__parsesections')
        assert self._status[_PARSE_SECTION] > _PARSE_QUERY, 'Inconsistent parse section when parsing ANSWER: %u' % self._status[_PARSE_SECTION]
        idx = self._status[_PARSE_SECTION] - _PARSE_ANSWER
        offset = self._status[_PARSE_OFFSET]
        sections = (('ANCOUNT', 'ANSWER'), ('NSCOUNT', 'AUTHORITY'), ('ARCOUNT', 'ADDITIONAL'))
        for count, name in sections[idx:]:
            self._dict[name] = []
            for i in range(self._dict['HEADER'][count]):
                dbg.msg('Starting to read %s[%u] section...' % (name, i))
                section, offset = self.__section(self._answer, offset)
                self._dict[name].append(section)

            self._status[_PARSE_SECTION] += 1
            self._status[_PARSE_OFFSET] = offset

        dbg.msg('ANSWER: %s' % self._dict)

    def __unpack16(self, value):
        dbg = _debug('_dnsanswer::__unpack16')
        return struct.unpack('>H', value)[0]

    def __unpack32(self, value):
        dbg = _debug('_dnsanswer::__unpack32')
        return struct.unpack('>L', value)[0]

    def __question(self, data, offset = 12):
        dbg = _debug('_dnsanswer::__question')
        res = {}
        res['DOMAIN'], offset = self.__domain(data, offset)
        res['TYPE'], offset = self.__dnstype(data, offset)
        res['CLASS'], offset = self.__dnsclass(data, offset)
        dbg.msg('QUESTION: %s' % res)
        return (res, offset)

    def __section(self, data, offset):
        dbg = _debug('_dnsanswer::__section')
        res = {}
        res['DOMAIN'], offset = self.__domain(data, offset)
        res['TYPE'], offset = self.__dnstype(data, offset)
        res['CLASS'], offset = self.__dnsclass(data, offset)
        res['TTL'], offset = self.__ttl(data, offset)
        rdlen, offset = self.__rdlength(data, offset)
        res['RDATA'], offset = self.__rdata(data, offset, rdlen, res['TYPE'])
        dbg.msg('SECTION: %s' % res)
        return (res, offset)

    def __sentry(self, datalen, reqlen):
        if datalen < reqlen:
            raise IncompleteAnswerError('Answer is incomplete')

    def __domain(self, data, offset):
        dbg = _debug('_dnsanswer::__domain')
        datalen = len(data)
        self.__sentry(datalen, offset + 2)
        anoffset = self.__islink(data, offset)
        if anoffset:
            token, anoffset = self.__domain(data, anoffset)
            return (token, offset + 2)
        tokenlist = []
        tokenlen = ord(data[offset])
        while tokenlen:
            self.__sentry(datalen, offset + tokenlen + 1)
            tokenlist.append(data[offset + 1:offset + tokenlen + 1])
            dbg.msg('Token found: %s' % tokenlist[-1])
            offset += tokenlen + 1
            self.__sentry(datalen, offset + 1)
            anoffset = self.__islink(data, offset)
            if anoffset:
                token, anoffset = self.__domain(data, anoffset)
                tokenlist.append(token)
                offset += 1
                break
            else:
                tokenlen = ord(data[offset])

        return (string.join(tokenlist, '.'), offset + 1)

    def __IPv4(self, data, offset):
        dbg = _debug('_dnsanswer::__IPv4')
        self.__sentry(len(data), offset + 4)
        length = 4
        ipaddrlist = []
        while length:
            ipaddrlist.append(str(ord(data[offset])))
            offset += 1
            length -= 1

        return (string.join(ipaddrlist, '.'), offset)

    def __IPv6(self, data, offset, length):
        dbg = _debug('_dnsanswer::__IPv6')
        self.__sentry(len(data), offset + length)
        ret = ''
        prev_empty = False
        if ord(data[offset]) == 0:
            prev_empty = True
        else:
            ret = '%X' % ord(data[offset])
        ret += ':'
        length -= 1
        offset += 1
        while length:
            if ord(data[offset]) > 0:
                if prev_empty:
                    ret += ':'
                ret += '%X:' % ord(data[offset])
            else:
                prev_empty = True
            length -= 1
            offset += 1

        return (ret[:-1], offset)

    def __strval(self, data, offset):
        dbg = _debug('_dnsanswer::__strval')
        strlen = ord(data[offset])
        self.__sentry(len(data), offset + strlen + 1)
        offset += 1
        retstr = data[offset:offset + strlen]
        return (retstr, offset + strlen)

    def __islink(self, data, offset):
        dbg = _debug('_dnsanswer::__islink')
        if len(data[offset:]) < 2:
            dbg.msg('Last octet in sequence (%u)' % offset)
            return 0
        self.__sentry(len(data), offset + 2)
        word = self.__unpack16(data[offset:offset + 2])
        if word / 16384 == 3:
            dbg.msg('Following link from offset %u to offset %u' % (offset, word & 16383))
            return word & 16383
        dbg.msg('Not a link at offset %u' % offset)
        return 0

    def __twobytes(self, data, offset):
        offset_end = offset + 2
        self.__sentry(len(data), offset_end)
        ret = self.__unpack16(data[offset:offset_end])
        return (ret, offset_end)

    def __fourbytes(self, data, offset):
        offset_end = offset + 4
        self.__sentry(len(data), offset_end)
        ret = self.__unpack32(data[offset:offset_end])
        return (ret, offset_end)

    def __dnsclass(self, data, offset):
        dbg = _debug('_dnsanswer::__dnsclass')
        return self.__twobytes(data, offset)

    def __dnstype(self, data, offset):
        dbg = _debug('_dnsanswer::__dnstype')
        return self.__twobytes(data, offset)

    def __ttl(self, data, offset):
        dbg = _debug('_dnsanswer::__ttl')
        return self.__fourbytes(data, offset)

    def __rdlength(self, data, offset):
        dbg = _debug('_dnsanswer::__rdlength')
        return self.__twobytes(data, offset)

    def __CNAME_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__CNAME_RDATA')
        return self.__domain(data, offset)

    def __HINFO_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__HINFO_RDATA')
        res = {}
        res['CPU'], offset = self.__strval(data, offset)
        res['OS'], offset = self.__strval(data, offset)
        return (res, offset)

    def __MB_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__MB_RDATA')
        return self.__domain(data, offset)

    def __MD_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__MD_RDATA')
        return self.__domain(data, offset)

    def __MF_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__MF_RDATA')
        return self.__domain(data, offset)

    def __MG_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__MG_RDATA')
        return self.__domain(data, offset)

    def __MINFO_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__MINFO_RDATA')
        res = {}
        res['RMAILBX'], offset = self.__domain(data, offset)
        res['EMAILBX'], offset = self.__domain(data, offset)
        return (res, offset)

    def __MR_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__MR_RDATA')
        return self.__domain(data, offset)

    def __MX_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__MX_RDATA')
        res = {}
        res['REFERENCE'], offset = self.__twobytes(data, offset)
        res['DOMAIN'], offset = self.__domain(data, offset)
        return (res, offset)

    def __NULL_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__NULL')
        return self.__UNKNOWN_RDATA(data, offset, length)

    def __NS_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__NS_RDATA')
        return self.__domain(data, offset)

    def __PTR_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__PTR_RDATA')
        return self.__domain(data, offset)

    def __SOA_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__SOA_RDATA')
        res = {}
        res['MNAME'], offset = self.__domain(data, offset)
        res['RNAME'], offset = self.__domain(data, offset)
        res['SERIAL'], offset = self.__fourbytes(data, offset)
        res['REFRESH'], offset = self.__fourbytes(data, offset)
        res['RETRY'], offset = self.__fourbytes(data, offset)
        res['EXPIRE'], offset = self.__fourbytes(data, offset)
        res['MINIMUM'], offset = self.__fourbytes(data, offset)
        return (res, offset)

    def __TXT_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__TXT_RDATA')
        return self.__strval(data, offset)

    def __A_RDATA(self, data, offset, length = 4):
        dbg = _debug('_dnsanswer::__A_RDATA')
        return self.__IPv4(data, offset)

    def __AAAA_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__AAAA_RDATA')
        return self.__IPv6(data, offset, length)

    def __AFSDB_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__AFSDB_RDATA')
        res = {}
        res['TYPE'], offset = self.__twobytes(data, offset)
        res['DOMAIN'], offset = self.__domain(data, offset)
        return (res, offset)

    def __RP_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__RP_RDATA')
        res = {}
        res['MBOX'], offset = self.__domain(data, offset)
        res['TXT'], offset = self.__domain(data, offset)
        return (res, offset)

    def __X25_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__X25_RDATA')
        return self.__strval(data, offset)

    def __ISDN_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__ISDN_RDATA')
        res = {}
        res['ISDN'], offset = self.__strval(data, offset)
        if len(res['ISDN']) + 1 < length:
            res['SA'], offset = self.__strval(data, offset)
        return (res, offset)

    def __RT_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__RT_RDATA')
        res = {}
        res['REFERENCE'], offset = self.__twobytes(data, offset)
        res['ROUTE'], offset = self.__domain(data, offset)
        return (res, offset)

    def __GPOS_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__GPOS_RDATA')
        res = {}
        res['LONGITUDE'], offset = self.__strval(data, offset)
        res['LATITUDE'], offset = self.__strval(data, offset)
        res['ALTITUDE'], offset = self.__strval(data, offset)
        return (res, offset)

    def __WKS_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__WKS_RDATA')
        assert length > 4, 'Inconsistent WKS RDATA length %u' % length
        self.__sentry(len(data), offset + length)
        res = {}
        res['ADDRESS'], offset = self.__IPv4(data, offset)
        res['PROTOCOL'] = ord(data[offset])
        offset += 1
        res['SERVICES'] = []
        octetno = 0
        for i in range(offset, offset + length - 5):
            val = ord(data[i])
            for j in range(7, 0, -1):
                if val & 1 << j:
                    res['SERVICES'].append(7 - j + 8 * octetno)

            octetno += 1

        return (res, offset + octetno)

    def __SRV_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__SRV_RDATA')
        res = {}
        res['PRIORITY'], offset = self.__twobytes(data, offset)
        res['WEIGHT'], offset = self.__twobytes(data, offset)
        res['PORT'], offset = self.__twobytes(data, offset)
        res['DOMAIN'], offset = self.__domain(data, offset)
        return (res, offset)

    def __KX_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__KX_RDATA')
        res = {}
        res['PREFERENCE'], offset = self.__twobytes(data, offset)
        res['DOMAIN'], offset = self.__domain(data, offset)
        return (res, offset)

    def __APL_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__APL_RDATA')
        self.__sentry(len(data), offset + length)
        res = {}
        res['AF'], offset = self.__twobytes(data, offset)
        res['PREFIX'] = ord(data[offset])
        offset += 1
        tmpvar = ord(data[offset])
        res['NEGATION'] = False
        if tmpvar & 128:
            res['NEGATION'] = True
        afdlen = tmpvar & 127
        offset += 1
        AF_INET = 1
        AF_INET6 = 2
        if res['AF'] == AF_INET:
            if res['PREFIX'] > 32:
                raise AnswerError('Wrong PREFIX %u in ARL RR' % res['PREFIX'])
            if afdlen > 4:
                raise AnswerError('Wrong AFDLENGTH %u for AF_INET' % afdlen)
            ipaddrlist = []
            while afdlen:
                ipaddrlist.append(str(ord(data[offset])))
                offset += 1
                afdlen -= 1

            res['AFD'] = string.join(ipaddrlist, '.')
        elif res['AF'] == AF_INET6:
            if res['PREFIX'] > 128:
                raise AnswerError('Wrong PREFIX %u in ARL RR' % res['PREFIX'])
            if afdlen > 16:
                raise AnswerError('Wrong AFDLENGTH %u for AF_INET6' % afdlen)
            res['AFD'], offset = self.__IPv6(data, offset, afdlen)
        else:
            raise AnswerError('Unknown Address Family %u' % res['AF'])
        return (res, offset)

    def __PX_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__PX_RDATA')
        res = {}
        res['PREFERENCE'], offset = self.__twobytes(data, offset)
        res['MAP822'], offset = self.__domain(data, offset)
        res['MAPX400'], offset = self.__domain(data, offset)
        return (res, offset)

    def __LOC_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__LOC_RDATA')
        self.__sentry(len(data), offset + length)
        res = {}
        res['VERSION'] = ord(data[offset])
        offset += 1
        res['SIZE'] = ord(data[offset])
        offset += 1
        res['HORIZ_PRE'] = ord(data[offset])
        offset += 1
        res['VERT_PRE'] = ord(data[offset])
        offset += 1
        res['LATITUDE'], offset = self.__fourbytes(data, offset)
        res['LONGITUDE'], offset = self.__fourbytes(data, offset)
        res['ALTITUDE'], offset = self.__fourbytes(data, offset)
        return (res, offset)

    def __NAPTR_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__NAPTR_RDATA')
        res = {}
        res['ORDER'], offset = self.__twobytes(data, offset)
        res['PREFERENCE'], offset = self.__twobytes(data, offset)
        res['FLAGS'], offset = self.__strval(data, offset)
        res['SERVICE'], offset = self.__strval(data, offset)
        res['REGEXP'], offset = self.__strval(data, offset)
        res['REPLACEMENT'], offset = self.__domain(data, offset)
        return (res, offset)

    def __UNKNOWN_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__UNKNOWN_RDATA')
        self.__sentry(len(data), offset + length)
        res = "Unsupported TYPE: '%s'" % data[offset:offset + length]
        return (res, offset + length)

    def __rdata(self, data, offset, length, atype):
        dbg = _debug('_dnsanswer::__rdata')
        if atype == T_A:
            return self.__A_RDATA(data, offset, length)
        if atype == T_NS:
            return self.__NS_RDATA(data, offset, length)
        if atype == T_MD:
            return self.__MD_RDATA(data, offset, length)
        if atype == T_MF:
            return self.__MF_RDATA(data, offset, length)
        if atype == T_CNAME:
            return self.__CNAME_RDATA(data, offset, length)
        if atype == T_SOA:
            return self.__SOA_RDATA(data, offset, length)
        if atype == T_MB:
            return self.__MB_RDATA(data, offset, length)
        if atype == T_MG:
            return self.__MG_RDATA(data, offset, length)
        if atype == T_MR:
            return self.__MR_RDATA(data, offset, length)
        if atype == T_NULL:
            return self.__NULL_RDATA(data, offset, length)
        if atype == T_WKS:
            return self.__WKS_RDATA(data, offset, length)
        if atype == T_PTR:
            return self.__PTR_RDATA(data, offset, length)
        if atype == T_HINFO:
            return self.__HINFO_RDATA(data, offset, length)
        if atype == T_MINFO:
            return self.__MINFO_RDATA(data, offset, length)
        if atype == T_MX:
            return self.__MX_RDATA(data, offset, length)
        if atype == T_TXT:
            return self.__TXT_RDATA(data, offset, length)
        if atype == T_AFSDB:
            return self.__AFSDB_RDATA(data, offset, length)
        if atype == T_RP:
            return self.__RP_RDATA(data, offset, length)
        if atype == T_X25:
            return self.__X25_RDATA(data, offset, length)
        if atype == T_ISDN:
            return self.__ISDN_RDATA(data, offset, length)
        if atype == T_RT:
            return self.__RT_RDATA(data, offset, length)
        if atype == T_GPOS:
            return self.__GPOS_RDATA(data, offset, length)
        if atype == T_AAAA:
            return self.__AAAA_RDATA(data, offset, length)
        if atype == T_LOC:
            return self.__LOC_RDATA(data, offset, length)
        if atype == T_SRV:
            return self.__SRV_RDATA(data, offset, length)
        if atype == T_NAPTR:
            return self.__NAPTR_RDATA(data, offset, length)
        if atype == T_KX:
            return self.__KX_RDATA(data, offset, length)
        if atype == T_APL:
            return self.__APL_RDATA(data, offset, length)
        if atype == T_PX:
            return self.__PX_RDATA(data, offset, length)
        return self.__UNKNOWN_RDATA(data, offset, length)

    def __opcodes(self, value):
        dbg = _debug('_dnsanswer::__opcodes')
        opcodes = self.__unpack16(value)
        dict = {}
        dict['Z'] = (opcodes & _HDR_RESERVED_MASK) / 16
        dict['QR'] = False
        if opcodes & _HDR_RESPONSE:
            dict['QR'] = True
        dict['OPCODE'] = (opcodes & _HDR_OPCODE_MASK) / 2048
        dict['AA'] = False
        if opcodes & _HDR_AUTH_ANSWER:
            dict['AA'] = True
        dict['TC'] = False
        if opcodes & _HDR_TRUNCATION:
            dict['TC'] = True
        dict['RD'] = False
        if opcodes & _HDR_REC_DESIRED:
            dict['RD'] = True
        dict['RA'] = False
        if opcodes & _HDR_REC_AVAIL:
            dict['RA'] = True
        dict['RCODE'] = opcodes & _HDR_RCODE_MASK
        dbg.msg('OPCODES: %s' % dict)
        return dict

    def __str__(self):
        if not self._complete:
            return 'Incomplete answer'
        res = ''
        res += 'ID: %u\n' % self._dict['HEADER']['ID']
        res += 'OPCODES: %s\n' % self._dict['HEADER']['OPCODES']
        if self._dict['HEADER']['OPCODES']['RCODE']:
            try:
                res += 'ERROR: %s\n' % HDR_RCODE[self._dict['HEADER']['OPCODES']['RCODE']][0]
            except KeyError:
                res += 'ERROR: Unknown Error %u\n' % self._dict['HEADER']['OPCODES']['RCODE']

        res += 'QDCOUNT: %u\n' % self._dict['HEADER']['QDCOUNT']
        res += 'ANCOUNT: %u\n' % self._dict['HEADER']['ANCOUNT']
        res += 'NSCOUNT: %u\n' % self._dict['HEADER']['NSCOUNT']
        res += 'ARCOUNT: %u\n' % self._dict['HEADER']['ARCOUNT']
        res += 'QUERY: %s\n' % self._dict['QUERY']
        res += 'ANSWER: %s\n' % self._dict['ANSWER']
        res += 'AUTHORITY: %s\n' % self._dict['AUTHORITY']
        res += 'ADDITIONAL: %s\n' % self._dict['ADDITIONAL']
        return res

    def id(self):
        return self._dict['HEADER']['ID']

    def isComplete(self):
        dbg = _debug('_dnsanswer::isComplete(%s)' % self._complete)
        return self._complete

    def get(self):
        return self._dict

    def add(self, chunk):
        dbg = _debug('_dnsanswer::add')
        self._answer += chunk
        if self._prefix:
            if self._size == 0 and len(self._answer) > 2:
                self._size = self.__twobytes(self._answer, 0)[0]
                dbg.msg('TCP Message Length: %u' % self._size)
                assert self._size > 0, 'Inconsistent length in TCP response'
                self._answer = self._answer[2:]
        else:
            dbg.msg('UDP Message Length: %u' % len(self._answer))
        self.__parse()
        if self._prefix:
            return self._size - len(self._answer)
        return 0

    def error(self):
        errcode = self._dict['HEADER']['OPCODES']['RCODE']
        errstr = 'Unknown Error %u' % errcode
        if errcode:
            if HDR_RCODE.has_key(errcode):
                errstr = HDR_RCODE[errcode][0]
        else:
            errstr = 'No Error'
        return (errcode, errstr)


_PROTOCOLS = {'udp': socket.SOCK_DGRAM,
 'tcp': socket.SOCK_STREAM}

class _dnsserver():

    def __init__(self, host, defport = 53, proto = None):
        self._serverport = defport
        self._serverproto = 'udp'
        hoststruct = host.split(':', 2)
        structlen = len(hoststruct)
        if structlen == 2:
            if _PROTOCOLS.has_key(hoststruct[0].lower()):
                self._serverproto = hoststruct[0].lower()
                self._servername = hoststruct[1]
            else:
                self._servername = hoststruct[0]
                self._serverport = int(hoststruct[1])
        elif structlen == 3:
            if not _PROTOCOLS.has_key(hoststruct[0].lower()):
                raise KeyError('Invalid connection protocol name: %s' % proto)
            self._serverproto = hoststruct[0].lower()
            self._servername = hoststruct[1]
            self._serverport = int(hoststruct[2])
        else:
            self._servername = hoststruct[0]
        if proto is not None:
            if _PROTOCOLS.has_key(proto):
                self._serverproto = proto
            else:
                raise KeyError('Invalid connection protocol name: %s' % proto)

    def proto(self):
        return _PROTOCOLS[self._serverproto]

    def name(self):
        return self._servername

    def port(self):
        return self._serverport

    def __str__(self):
        return '%s:%s:%u' % (self._serverproto, self._servername, self._serverport)


class _dnsconnection():

    def __init__(self, srv = None, timeout = 10):
        dbg = _debug('_dnsconnection::__init__')
        self._connected = False
        self._proto = srv.proto()
        self._name = srv.name()
        self._port = srv.port()
        self._timeout = timeout
        self._socket = socket.socket(socket.AF_INET, self._proto)
        self._fd = self._socket.fileno()

    def useprefix(self):
        if self._proto == socket.SOCK_STREAM:
            return True
        return False

    def connect(self):
        dbg = _debug('_dnsconnection::connect')
        self._socket.settimeout(self._timeout)
        self._socket.connect((self._name, self._port))
        self._connected = True

    def send(self, data):
        dbg = _debug('_dnsconnection::send')
        if not self._connected:
            dbg.msg('not connected')
            return
        self._socket.send(data)

    def __recv(self):
        dbg = _debug('_dnsconnection::__recv')
        if self._proto == socket.SOCK_STREAM:
            return self._socket.recv(512)
        answer, (host, port) = self._socket.recvfrom(262144)
        if not (host == self._name and port == self._port):
            raise ConnectionError('Request server %s:%u does not match response server %s:%u' % (self._name,
             self._port,
             host,
             port))
        return answer

    def recv(self, receiver):
        dbg = _debug('_dnsconnection::recv')
        if not self._connected:
            dbg.msg('not connected')
            return False
        togo = -1
        while togo:
            rl, wl, xl = select.select([self._fd], [], [], self._timeout)
            if self._fd in rl:
                togo = receiver.add(self.__recv())
            else:
                return False

        return True

    def disconnect(self):
        dbg = _debug('_dnsconnection::disconnect')
        if not self._connected:
            dbg.msg('not connected')
            return
        self._socket.close()
        self._connected = False

    def __str__(self):
        s = '%s:%s:%s: ' % (self._proto, self._name, self._port)
        if not self._connected:
            s += 'not '
        s += 'connected'
        return s


class Resolver():
    """
    Resolver class is used to send, receive, and parse DNS requests.
    
    When instantiating this class you may specify list of nameservers
    to use, port these name servers use, and a timeout for waiting for
    the name server response.
    
    In case the name servers weren't supplied /etc/resolv.conf is used.
    If /etc/resolv.conf does not contain information on name servers
    (or the file is missing, or other error), it is assumed that DNS
    server resides on localhost, port 53.
    
    In case the port wasn't specified port 53 is used.
    
    Default value for timeout is 10 seconds.
    
    Typical usage of this class is as follows:
    
        resolver = DNS.Resolver() # use /etc/resolv.conf, port 53, 10 sec
    
        ipaddrlist = resolver.IPAddress('some.host.com')
        print ipaddrlist
        # resolver found 3 addresses associated with the hostname
        ('192.168.0.1', '192.168.0.2', '192.168.0.3')
    
        mxlist = resolver.MailExchange('domain.com')
        print mxlist
        # mail for this domain is handled by 2 mail servers
        (('domain.com',), ((10, '192.168.0.10'), (20, '192.168.0.20')),)
    
    For more comprehensive information use Raw() method.
    """

    def __init__(self, nameservers = None, port = 53, timeout = 0):
        dbg = _debug('Resolver::__init__')
        self._servers = nameservers or _DNSSERVERS or ['udp:127.0.0.1:53']
        self._port = port or 53
        self._timeout = timeout or 10
        self._candidates = []

    def __str__(self):
        fmt = 'Name servers: %s\nCandidate Domains: %s\nTimeout: %u sec'
        return fmt % (self._servers, self._candidates, self._timeout)

    def __stripcomment(self, line, comments):
        dbg = _debug('Resolver::__stripcomment')
        line = line.strip()
        for br in comments:
            c = line.find(br)
            if c != -1:
                line = line[:c].strip()

        return line

    def __resolv_conf(self):
        dbg = _debug('Resolver::__resolv_conf')
        nameservers = []
        candidatedomains = []
        primarydomain = ''
        timeout = 0
        try:
            rawlines = open('/etc/resolv.conf', 'r').readlines()
        except:
            return ((), (), 0)

        comments = [';', '#']
        for line in rawlines:
            sl = self.__stripcomment(line, comments)
            if not sl:
                continue
            l = sl.split(' ')
            if l:
                if l[0] == 'nameserver':
                    for ns in l[1:]:
                        if ns not in nameservers:
                            nameservers.append(ns)

                elif l[0] == 'domain':
                    primarydomain = l[1]
                elif l[0] == 'search':
                    for domain in l[1:]:
                        if domain not in candidatedomains:
                            candidatedomains.append(domain)

                elif l[0] == 'options':
                    for option in l[1:]:
                        if option.startswith('timeout'):
                            timeout = int(option.split(':', 1)[1])

        if primarydomain and primarydomain not in candidatedomains:
            candidatedomains.insert(0, primarydomain)
            candidatedomains = _unique(candidatedomains)
        return (tuple(nameservers), tuple(candidatedomains), timeout)

    def __resolve(self, query, proto = None, nsserver = None):
        dbg = _debug('Resolver::__resolve')
        if not nsserver:
            nsserver = self._servers
        else:
            nsserver = (nsserver,)
        for server in nsserver:
            srv = _dnsserver(server, self._port, proto)
            conn = _dnsconnection(srv, self._timeout)
            answer = _dnsanswer(prefix=conn.useprefix())
            dbg.msg('Connecting to %s' % srv)
            conn.connect()
            try:
                dbg.msg('Sending query...')
                conn.send(query.get(conn.useprefix()))
                dbg.msg('Waiting for response...')
                if not conn.recv(answer):
                    dbg.msg('Request timed out, giving up')
            finally:
                conn.disconnect()

            if answer.isComplete():
                dbg.msg('Answer received')
                return answer
            dbg.msg('No answer from %s' % srv)

    def ixfr(self, domain, serial, mname, rname, recursion = True, proto = None):
        """
        Returns tuple of incremental changes of the domain zone records
        since serial version.
        
        mname is the name of the name server that was the original or
        primary source of data for this zone.
        
        rname is the mailbox of the person responsible for this zone.
        """
        soa = {'NAME': domain,
         'TYPE': T_SOA,
         'CLASS': C_IN}
        soa['RDATA'] = {'MNAME': mname,
         'RNAME': rname,
         'SERIAL': serial}
        sections = {'AUTHORITY': [soa]}
        res = self.Raw(domain, T_IXFR, C_IN, recursion, proto, sections)
        if res['HEADER']['ANCOUNT'] == 1:
            res = self.Raw(domain, T_IXFR, C_IN, recursion, 'tcp', sections)
        return tuple(res['ANSWER'])

    def CandidateDomains(self):
        """
        Returns possible domains of localhost
        """
        return tuple(self._candidates)

    def MailDomain(self, hostname, recursion = True, proto = None):
        """
        Returns possible mail domain the host belongs to.
        """
        dbg = _debug('Resolver::MailDomain')
        raw = self.Raw(hostname, T_MX, C_IN, recursion, proto, None)
        if raw['HEADER']['ANCOUNT'] > 0:
            return hostname
        hint = []
        if raw['HEADER']['NSCOUNT'] > 0:
            domains = []
            for nsrecord in raw['AUTHORITY']:
                domains.append(nsrecord['DOMAIN'])

            hint = _unique(domains)
            hint.sort()
            return hint[0]

    def Hostname(self, ipaddress, recursion = True, proto = None):
        """
        Returns immutable list of the IP address hostnames
        """
        dbg = _debug('Resolver::Hostname')
        raw = self.Raw(ipaddress, T_PTR, C_IN, recursion, proto, None)
        res = ()
        if raw['HEADER']['ANCOUNT'] > 0:
            for answer in raw['ANSWER']:
                res += (answer['RDATA'],)

        return res

    def NameServer(self, domain, recursion = True, proto = None):
        """
        Find name servers that serve the domain.
        Returns immutable list consisting of two elements: hints section
        which comprises possible domains that should be queried on behalf
        of the initial domain, and list of the names of the name servers.
        """
        dbg = _debug('Resolver::NameServer')
        raw = self.Raw(domain, T_NS, C_IN, recursion, proto, None)
        hint = []
        if raw['HEADER']['NSCOUNT'] > 0:
            domains = []
            for nsrecord in raw['AUTHORITY']:
                domains.append(nsrecord['DOMAIN'])

            hint = _unique(domains)
            hint.sort()
        ns = []
        if raw['HEADER']['ANCOUNT'] > 0:
            for nsrecord in raw['ANSWER']:
                ns.append(nsrecord['RDATA'])

        return (tuple(hint), tuple(ns))

    def MailExchange(self, domain, recursion = True, proto = None):
        """
        Find the domain mail servers, their preferences as well.
        Returned list consists of two elements - first comes the hint
        section comprised of possible domains that should be queried
        on behalf of the initial domain, the second one is list of
        found MX records for this domain.
        """
        dbg = _debug('Resolver::MailExchange')
        raw = self.Raw(domain, T_MX, C_IN, recursion, proto, None)
        hint = []
        if raw['HEADER']['NSCOUNT'] > 0:
            domains = []
            for nsrecord in raw['AUTHORITY']:
                domains.append(nsrecord['DOMAIN'])

            hint = _unique(domains)
            hint.sort()
        mx = []
        if raw['HEADER']['ANCOUNT'] > 0:
            for mxrecord in raw['ANSWER']:
                mx.append((mxrecord['RDATA']['REFERENCE'], mxrecord['RDATA']['DOMAIN']))

        return (tuple(hint), tuple(mx))

    def IPAddress(self, hostname, recursion = True, proto = None):
        """
        Find all IP addresses of the host by its name.
        Returns immutable list of the addresses.
        """
        dbg = _debug('Resolver::IPAddress')
        raw = self.Raw(hostname, T_A, C_IN, recursion, proto, None)
        res = ()
        if raw['HEADER']['ANCOUNT'] > 0:
            for answer in raw['ANSWER']:
                res += (answer['RDATA'],)

        return res

    def Raw(self, addr, qtype = T_A, qclass = C_IN, recursion = False, proto = None, sections = None, nsserver = None):
        """
        Resolve given hostname/IP address, query type, and query class.
        All other Resolver class methods like IPAddress(), MailExchange(),
        etc internally use this function.
        
        The query will be recursive if the recursion is set to True.
        
        Caller may set proto to 'udp' or 'tcp' to enforce
        the communication protocol regardless of name servers
        configuration. Omit this argument to use server settings.
        
        Returns complete DNS server response as dictionary with following
        keys:
            HEADER: Placeholder of header information. Has a dictionary
                    with keys:
                ID: id of DNS request
                OPCODES: Dictionary of server response values. Keys are:
                    QR: boolean field that specifies whether this message
                        is a query (False), or a response (True).
                    OPCODE: integer field that specifies kind of query in
                            this message. This value is set by originator
                            of query and copied into response. The values
                            are:
                            0 - a standard query
                            1 - an inverse query
                            2 - a server status request
                    AA: Authoritative Answer - this boolean value is valid
                        in responses, and specifies that the responding
                        name server is an authority for the domain name in
                        question section.
                    TC: TrunCation - specifies that this message was
                        truncated due to length greater than that permitted
                        on the transmission channel.
                    RD: Recursion Desired - this boolean may be set in
                        a query and is copied into the response. If RD is
                        set, it directs the name server to pursue the query
                        recursively. Recursive query support is optional.
                    RA: Recursion Available - this bit is set or cleared in
                        a response, and denotes whether recursive query
                        support is available in the name server.
                    Z: Reserved for future use. Must be zero in all queries
                       and responses.
                    RCODE: Response code - this field is set as part of
                           responses, see DNS_RCODE values.
                QDCOUNT: number of entries in the question section.
                ANCOUNT: number of resource records in the answer section.
                NSCOUNT: number of name server resource records in the
                         authority records section.
                ARCOUNT: number of resource records in the additional
                         records section.
            QUERY: list of the question section entries. Each entry is a
                   dictionary with keys:
                        DOMAIN: string of the queried domain name
                        TYPE: query type, see DNS_TYPE constants
                        CLASS: query class, see DNS_CLASS constants
            ANSWER: list of the answer section entries. Each entry is a
                    dictionary which keys are
                        DOMAIN: an owner name, i.e., the name of the node
                                to which this resource record pertains.
                        TYPE: RR type, see DNS_TYPE constants
                        CLASS: RR class, see DNS_CLASS constants
                        TTL: a 32 bit signed integer that specifies the
                             time interval that the resource record may
                             be cached before the source of the
                             information should again be consulted. Zero
                             values are interpreted to mean that the RR
                             can only be used for the transaction in
                             progress, and should not be cached. For
                             example, SOA records are always distributed
                             with a zero TTL to prohibit caching. Zero
                             values can also be used for extremely
                             volatile data.
                        RDATA: a variable length string that describes the
                               resource.  The format of this information
                               varies according to the TYPE and CLASS of
                               the resource record.
            AUTHORITY: list of the authority records section entries. Each
                       entry is a dictionary which keys are DOMAIN, TYPE,
                       CLASS, TTL, and RDATA, see ANSWER section
                       description.
            ADDITIONAL: list of the additonal records section entries. Each
                        entry is a dictionary which keys are DOMAIN, TYPE,
                        CLASS, TTL, and RDATA, see ANSWER section
                        description.
        """
        dbg = _debug('Resolver::Raw')
        if qtype == '*':
            qtype = T_ANY
        if qclass == '*':
            qclass = C_ANY
        query = _dnsquery((addr, qtype, qclass), sections, recursion)
        answer = self.__resolve(query, proto, nsserver=nsserver)
        if answer is None:
            raise ResolverError('None of the servers responded')
        if answer.isComplete():
            if query.id() == answer.id():
                e, s = answer.error()
                if e:
                    raise ServerError(s)
                return answer.get()
            raise ResolverError('Query ID %u does not match answer ID %u' % (query.id(), answer.id()))
        else:
            raise ResolverError('Truncated answer')


class DNSCache():
    """
    Covers the DNS object, keeps a cache of answers.  Clumsy as hell.
    """
    _hosts_dict = {}
    _wait_dict = {}
    _dns_dict = {}
    negCache = 3600
    retryCache = 10
    maxCache = 10000

    def __init__(self):
        self._dns = Resolver()
        self._lock = threading.RLock()
        try:
            hosts_file = None
            if os.name == 'nt':
                if os.getenv('WINDIR') != None:
                    hosts_file = os.getenv('WINDIR') + '\\System32\\drivers\\etc\\hosts'
            elif os.name == 'posix':
                hosts_file = '/etc/hosts'
            if hosts_file != None:
                for line in open(hosts_file):
                    m = re.match('^(\\d+\\.\\d+\\.\\d+\\.\\d+)\\s+([^\\s]+)$', line)
                    if m:
                        self._hosts_dict[m.group(2)] = m.group(1)

        except:
            pass

    def flush(self):
        self._lock.acquire()
        self._dns_dict.clear()
        self._lock.release()

    def lookup(self, name):
        if name in self._hosts_dict:
            return self._hosts_dict[name]
        for c in name:
            c = ord(c)
            if (c > 57 or c < 48) and c != 46:
                break
        else:
            return name

        ip = None
        event = None
        self._lock.acquire()
        if self._dns_dict.has_key(name):
            if self._dns_dict[name][1] < time.time():
                del self._dns_dict[name]
            else:
                ip = self._dns_dict[name][0]
        else:
            event = self._wait_dict.get(name)
        if not ip and not event:
            self._wait_dict[name] = threading.Event()
        self._lock.release()
        if event:
            event.wait(30)
            return self._dns_dict.get(name)[0]
        if ip:
            return ip
        answers = None
        try:
            r = self._dns.Raw(name, T_A, C_IN, True)
            if r['HEADER']['ANCOUNT'] > 0:
                answers = r['ANSWER']
        except:
            pass

        self._lock.acquire()
        if answers:
            for answer in answers:
                if answer['TYPE'] == T_A:
                    ip = answer['RDATA'].encode('ascii')
                    if len(self._dns_dict) > self.maxCache:
                        self._dns_dict.clear()
                    now = time.time()
                    self._dns_dict[name] = (ip, now + self.negCache if ip else now + self.retryCache)
                    break

        self._wait_dict[name].set()
        del self._wait_dict[name]
        self._lock.release()
        return ip


if __name__ == '__main__':
    dns = DNSCache()
    print dns.lookup('115.182.59.52')
    print dns.lookup('www.163.com')
    print dns.lookup('www.yascanner.com')
    
