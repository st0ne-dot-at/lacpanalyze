#!/bin/env python
from __future__ import print_function
import os, sys
import threading
import Queue
import re
from subprocess import Popen, PIPE
import signal
from pprint import pprint

DEVNULL = open(os.devnull, 'wb')

q = Queue.Queue()

class LacpSnoop(object):
    def __init__(self, i):
        self.i = i
        self.p = None
        self.pid = None
        self.regex = '.*, Key ([0-9]+),.*Partner.*'
        self.filter = ["ether", "dst", "host", "01:80:c2:00:00:02", "and", "not", "outbound"]
    def run(self, timeout):
        def target():
            self.p = Popen(["tcpdump", "-i", self.i, "-c1", "-s0", "-vvv"] + self.filter,
                           stdout=PIPE,
                           stderr=DEVNULL)
            self.pid = self.p.pid
            try:
           
                output = self.p.communicate()[0]
                output = re.match(self.regex, output.replace("\n", "")).groups()[0]
                print('INFO: match: %s on interface %s' % (output, self.i))
                q.put((self.i, output))
            except Exception as e:
                pass

        t = threading.Thread(target=target)
        t.setDaemon(True)
        t.start()
        t.join(timeout)
        
        try:
            os.kill(self.pid, signal.SIGKILL)
        except Exception as e:
            pass
        t.join(5)
        try:
            os.kill(self.pid, signal.SIGKILL)
        except Exception as e:
            pass
        t.join()
        
class VlanSnoop(LacpSnoop):
    def __init__(self, i):
        super(VlanSnoop, self).__init__(i) 
        self.regex = '.*Native VLAN ID .* bytes: ([0-9]+).*AVVID trust.*'
        self.filter = ["ether[20:2]==0x2000"]
        

if __name__ == '__main__':
    tmp_interfaces = os.listdir('/sys/class/net/')
    interfaces = []
    for i in tmp_interfaces:
        if i == 'lo' or i.startswith('bond'):
            continue
        with open('/sys/class/net/%s/operstate' % i, 'r') as f:
            if f.readline().replace("\n", "")  == 'up':
                interfaces.append(i)
    threads = []
    
    print("INFO: scanning interfaces (%s) for lacp port channels ... max 65 seconds" % ",".join(interfaces),
         file=sys.stderr)
    for i in interfaces:
        l = LacpSnoop(i)
        t = threading.Thread(target=l.run, args=(65,))
        t.setDaemon(True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    res = []
    while not q.empty():
        res.append(q.get())

    lacp = {}
    for r in res:
        lacp[r[1]] = lacp.get(r[1], []) + [r[0]]

    pprint(lacp)

    threads = []
    print("INFO: scanning interfaces (%s) for VLAN association ... max 65 seconds" % ",".join(interfaces),
         file=sys.stderr)
    for i in interfaces:
        l = VlanSnoop(i)
        t = threading.Thread(target=l.run, args=(65,))
        t.setDaemon(True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    res = []
    while not q.empty():
        res.append(q.get())

    vlan = {}
    for r in res:
        vlan[r[0]] = r[1]

    pprint(vlan)
