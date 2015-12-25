#! /usr/bin/python

"""
    Performs an iterative resolution of a DNS name, type, class, starting from
    the root DNS servers. Modified for the intent of using it inside my own
    Python scripts.
"""
__author__ = "Shumon Huque"
__copyright__ = "Copyright 2015, Shumon Huque"
__credits__ = ["Shumon Huque"]
__maintainer__ = ["John Lawrence M. Penafiel"]
__email__ = "penafieljlm@gmail.com"

import os, sys, getopt, time, random
import dns.message, dns.query, dns.rdatatype, dns.rcode, dns.dnssec

PROGNAME   = os.path.basename(sys.argv[0])
VERSION    = "0.14x"
ROOTHINTS  = [
    ('a.root-servers.net.', '198.41.0.4'), 
    ('a.root-servers.net.', '2001:503:ba3e::2:30'), 
    ('b.root-servers.net.', '192.228.79.201'), 
    ('b.root-servers.net.', '2001:500:84::b'), 
    ('c.root-servers.net.', '192.33.4.12'), 
    ('c.root-servers.net.', '2001:500:2::c'), 
    ('d.root-servers.net.', '199.7.91.13'), 
    ('d.root-servers.net.', '2001:500:2d::d'), 
    ('e.root-servers.net.', '192.203.230.10'), 
    ('f.root-servers.net.', '192.5.5.241'), 
    ('f.root-servers.net.', '2001:500:2f::f'), 
    ('g.root-servers.net.', '192.112.36.4'), 
    ('h.root-servers.net.', '128.63.2.53'), 
    ('h.root-servers.net.', '2001:500:1::803f:235'), 
    ('i.root-servers.net.', '192.36.148.17'), 
    ('i.root-servers.net.', '2001:7fe::53'), 
    ('j.root-servers.net.', '192.58.128.30'), 
    ('j.root-servers.net.', '2001:503:c27::2:30'), 
    ('k.root-servers.net.', '193.0.14.129'), 
    ('k.root-servers.net.', '2001:7fd::1'), 
    ('l.root-servers.net.', '199.7.83.42'), 
    ('l.root-servers.net.', '2001:500:3::42'), 
    ('m.root-servers.net.', '2001:dc3::35'), 
    ('m.root-servers.net.', '202.12.27.33')
]

# TODO: remove this
MAX_CNAME  = 10                           # Max #CNAME indirections
MAX_QUERY  = 300                          # Max number of queries
MAX_DELEG  = 26                           # Max number of delegations

class Prefs:
    """Preferences"""
    DEBUG      = False                    # -d: Print debugging output?
    MINIMIZE   = False                    # -m: Do qname minimization?
    TCPONLY    = False                    # -t: Use TCP only
    VERBOSE    = False                    # -v: Trace query->zone path
    VIOLATE    = False                    # -x: ENT nxdomain workaround
    STATS      = False                    # -s: Print statistics
    NSRESOLVE  = False                    # -n: Resolve all NS addresses
    BATCHFILE  = None                     # -b: batch file mode

class Stats:
    """Statistics counters"""
    cnt_cname        = 0
    cnt_query1       = 0                  # regular queries
    cnt_query2       = 0                  # NS address queries
    cnt_fail         = 0
    cnt_tcp          = 0
    cnt_deleg        = 0
    delegation_depth = 0

class Cache:
    """Cache of Zone & NameServer objects"""
    ZoneDict   = dict()                   # dns.name.Name -> Zone
    NSDict     = dict()                   # dns.name.Name -> NameServer

class Query:
    """Query name class"""

    def __init__(self, qname, qtype, qclass, minimize=False):
        if isinstance(qname, dns.name.Name):
            self.qname = qname
        else:
            self.qname = dns.name.from_text(qname)
        self.orig_qname = self.qname
        self.qtype = qtype
        self.qclass = qclass
        self.minimize = minimize
        self.quiet = False                     
        self.rcode = None
        self.got_answer = False
        self.cname_chain = []
        self.answer_rrset = []
        self.full_answer_rrset = []
        self.zone_chain = []
        self.forced_break = False

    def get_answer_ip_list(self):
        iplist = []
        for rrset in self.full_answer_rrset:
            if rrset.rdtype in [dns.rdatatype.A, dns.rdatatype.AAAA]:
                for rr in rrset:
                    iplist.append(rr.to_text())
        return iplist

    def set_minimized(self, zone):
        labels_qname = self.orig_qname.labels
        labels_zone = zone.name.labels
        minLabels = len(labels_zone) + 1
        self.qname = dns.name.Name(labels_qname[-minLabels:])

    def prepend_label(self):
        numLabels = len(self.qname) + 1
        self.qname = dns.name.Name(self.orig_qname[-numLabels:])

    def __repr__(self):
        return "<Query: %s,%s,%s>" % (self.qname, self.qtype, self.qclass)


class IPaddress:
    """IPaddress class"""

    def __init__(self, ip):
        self.addr = ip
        self.addrtype = None
        self.rtt = float('inf')                    # RTT for UDP
        self.query_count = 0

    def __repr__(self):
        return "<IPaddress: %s>" % self.addr


class NameServer:
    """NameServer class"""

    def __init__(self, name):
        self.name = name                           # dns.name.Name
        self.iplist = []                           # list of IPaddress

    def has_ip(self, ipstring):
        if ipstring in [x.addr for x in self.iplist]:
            return True
        else:
            return False

    def install_ip(self, ipstring):
        if not self.has_ip(ipstring):
            self.iplist.append(IPaddress(ipstring))
        return

    def __repr__(self):
        return "<NS: %s>" % self.name


class Zone:
    """Zone class"""

    def __init__(self, zone):
        self.name = zone                           # dns.name.Name
        self.nslist = []                           # list of dns.name.Name
        Cache.ZoneDict[zone] = self

    def has_ns(self, ns):
        if ns in self.nslist:
            return True
        else:
            return False

    def install_ns(self, nsname, clobber=False):
        """Install a nameserver record for this zone"""
        if nsname not in self.nslist:
            self.nslist.append(nsname)
        if clobber or (nsname not in Cache.NSDict):
            Cache.NSDict[nsname] = NameServer(nsname)
        return Cache.NSDict[nsname]

    def iplist(self):
        result = []
        for ns in self.nslist:
            result += Cache.NSDict[ns].iplist
        return result

    def iplist_sorted_by_rtt(self):
        return sorted(self.iplist(), key=lambda ip: ip.rtt)

    def __repr__(self):
        return "<Zone: %s>" % self.name


def get_root_zone():
    """populate the Root Zone object from hints file"""
    z = Zone(dns.name.root)
    for name, addr in ROOTHINTS:
        name = dns.name.from_text(name)
        nsobj = z.install_ns(name, clobber=False)
        nsobj.install_ip(addr)
    return z


def closest_zone(qname):
    """given query name, find closest enclosing zone object in Cache"""
    for z in reversed(sorted(Cache.ZoneDict.keys())):
        if qname.is_subdomain(z):
            return Cache.ZoneDict[z]
    else:
        return Cache.ZoneDict[dns.name.root]


def get_ns_addrs(zone, message, stats, timeout=3):
    """
    Populate nameserver addresses for zone.
    
    Note: by default, we only save and use NS record addresses we can find 
    in the additional section of the referral. To be complete, we should 
    really explicitly resolve all non-glue NS addresses, which results in a 
    large number of additional queries and corresponding latency. This 
    complete mode can be turned on with -n (NSRESOLVE). If no NS addresses
    can be found in the additional section, we resort to NSRESOLVE mode.
    """

    global Prefs

    needsGlue = []
    for nsname in zone.nslist:
        if nsname.is_subdomain(zone.name):
            needsGlue.append(nsname)
    needToResolve = list(set(zone.nslist) - set(needsGlue))

    for rrset in message.additional:
        if rrset.rdtype in [dns.rdatatype.A, dns.rdatatype.AAAA]:
            name = rrset.name
            for rr in rrset:
                if not zone.has_ns(name):
                    continue
                if (not Prefs.NSRESOLVE) or (name in needsGlue):
                    nsobj = Cache.NSDict[name]
                    nsobj.install_ip(rr.address)

    if not zone.iplist() or Prefs.NSRESOLVE:       
        for name in needToResolve:
            nsobj = Cache.NSDict[name]
            if nsobj.iplist:
                continue
            for addrtype in ['A', 'AAAA']:
                nsquery = Query(name, addrtype, 'IN', Prefs.MINIMIZE)
                nsquery.quiet = True
                resolve_name(nsquery, closest_zone(nsquery.qname), stats, timeout=timeout, inPath=False, nsQuery=True)
                for ip in nsquery.get_answer_ip_list():
                    nsobj.install_ip(ip)

    return


def process_referral(message, query, stats, timeout=3):

    """Process referral. Returns a zone object for the referred zone"""
    global Prefs

    for rrset in message.authority:
        if rrset.rdtype == dns.rdatatype.NS:
            break
    else:
        return None

    zonename = rrset.name
    if zonename in Cache.ZoneDict:
        zone = Cache.ZoneDict[zonename]
    else:
        zone = Zone(zonename)
        for rr in rrset:
            nsobj = zone.install_ns(rr.target)

    get_ns_addrs(zone, message, stats, timeout=timeout)
    return zone


def process_answer(response, query, stats, timeout=3, addResults=None):

    """Process answer section, chasing aliases when needed"""

    global Prefs
    answer = response.answer

    # If minimizing, then we ignore answers for intermediate query names.
    if query.qname != query.orig_qname:
        return answer

    empty_answer = (len(answer) == 0)

    for rrset in answer:
        if rrset.rdtype == dns.rdatatype.from_text(query.qtype) and \
            rrset.name == query.qname:
                query.answer_rrset.append(rrset)
                addResults and addResults.full_answer_rrset.append(rrset)
                query.got_answer = True
        elif rrset.rdtype == dns.rdatatype.DNAME:
            query.answer_rrset.append(rrset)
            addResults and addResults.full_answer_rrset.append(rrset)
        elif rrset.rdtype == dns.rdatatype.CNAME:
            query.answer_rrset.append(rrset)
            addResults and addResults.full_answer_rrset.append(rrset)
            cname = rrset[0].target
            stats.cnt_cname += 1
            if stats.cnt_cname >= MAX_CNAME:
                return None
            else:
                cname_query = Query(cname, query.qtype, query.qclass, Prefs.MINIMIZE)
                addResults and addResults.cname_chain.append(cname_query)
                resolve_name(cname_query, closest_zone(cname), stats, timeout=timeout,
                             inPath=False, addResults=addResults)
                for zone in cname_query.zone_chain:
                    query.zone_chain.append(zone)
    return answer


def process_response(response, query, stats, timeout=3, addResults=None):

    """process a DNS response. Returns rcode, answer message, zone referral"""

    rc = None; ans = None; referral = None
    if not response:
        return (rc, ans, z)
    rc = response.rcode()
    query.rcode = rc
    aa = (response.flags & dns.flags.AA == dns.flags.AA)
    if rc == dns.rcode.NOERROR:
        answerlen = len(response.answer)
        if answerlen == 0 and not aa:                    # Referral
            referral = process_referral(response, query, stats, timeout=timeout)
        else:                                            # Answer
            ans = process_answer(response, query, stats, timeout=timeout, addResults=addResults)

    return (rc, ans, referral)


def update_query_counts(stats, ip, nsQuery=False, tcp=False):
    """Update query counts in Statistics"""
    ip.query_count += 1
    if tcp:
        stats.cnt_tcp += 1
    else:
        if nsQuery:
            stats.cnt_query2 += 1
        else:
            stats.cnt_query1 += 1
    return


def send_query(query, zone, stats, timeout=3, nsQuery=False):
    """send DNS query to nameservers of given zone"""
    global Prefs
    response = None

    msg = dns.message.make_query(query.qname, query.qtype, rdclass=query.qclass)
    msg.flags ^= dns.flags.RD

    nsaddr_list = zone.iplist_sorted_by_rtt();
    if len(nsaddr_list) == 0:
        return response

    for nsaddr in nsaddr_list:
        if stats.cnt_query1 + stats.cnt_query2 >= MAX_QUERY:
            return response
        try:
            update_query_counts(stats, ip=nsaddr, nsQuery=nsQuery)
            msg.id = random.randint(1, 65535)          # randomize txid
            truncated = False
            if not Prefs.TCPONLY:
                t1 = time.time()
                response = dns.query.udp(msg, nsaddr.addr, timeout=timeout,
                                         ignore_unexpected=True)
                t2 = time.time()
                nsaddr.rtt = (t2 - t1)
                truncated = (response.flags & dns.flags.TC == dns.flags.TC)
            if Prefs.TCPONLY or truncated:
                update_query_counts(stats, ip=nsaddr, nsQuery=nsQuery, tcp=True)
                response = dns.query.tcp(msg, nsaddr.addr, timeout=timeout)
        except Exception as e:
            stats.cnt_fail += 1
            pass
        else:
            rc = response.rcode()
            if rc not in [dns.rcode.NOERROR, dns.rcode.NXDOMAIN]:
                stats.cnt_fail += 1
            else:
                break

    return response


def resolve_name(query, zone, stats, timeout=3, inPath=True, nsQuery=False, addResults=None, callback=None):
    """resolve a DNS query. addResults is an optional Query object to
    which the answer results are to be added."""

    global Prefs
    curr_zone = zone
    repeatZone = False

    while stats.cnt_deleg < MAX_DELEG:

        if query.minimize:
            if repeatZone:
                query.prepend_label()
                repeatZone = False
            else:
                query.set_minimized(curr_zone)

        query.zone_chain.append(curr_zone)

        if callback is not None:
            if callback([[ns.to_text()[:-1] for ns in zone.nslist] for zone in query.zone_chain]):
                query.forced_break = True
                return
        
        response = send_query(query, curr_zone, stats, timeout=timeout, nsQuery=nsQuery)
        
        if not response:
            return

        rc, ans, referral = process_response(response, query, stats, timeout=timeout, addResults=addResults)

        if rc == dns.rcode.NXDOMAIN:
            # for broken servers that give NXDOMAIN for empty non-terminals
            if Prefs.VIOLATE and (query.minimize) and (query.qname != query.orig_qname):
                repeatZone = True
            else:
                break

        if not referral:
            if (not query.minimize) or (query.qname == query.orig_qname):
                break
            elif query.minimize:
                repeatZone = True
        else:
            stats.cnt_deleg += 1
            if inPath:
                stats.delegation_depth += 1
            curr_zone = referral

    return

def resolve(domain, timeout=3, callback=None):
    random.seed(os.urandom(64))
    query = Query(domain, 'A', 'IN', minimize=Prefs.MINIMIZE)
    stats = Stats()
    resolve_name(query, get_root_zone(), stats, timeout=timeout, addResults=query, callback=callback)
    return (
            query.get_answer_ip_list(),
            [[ns.to_text()[:-1] for ns in zone.nslist] for zone in query.zone_chain],
            query.forced_break
            )
