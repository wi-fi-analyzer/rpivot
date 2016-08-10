__author__ = 'artem'
import socket
import select
import errno
import time


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setblocking(0)

err = sock.connect_ex(('127.0.0.1', 1024))
print 'after blocking'
#sock.setblocking(1)

while True:
    r, w, e = select.select([sock], [sock], [sock])
    print r, w, e
    #print r[0].recv(1024)
    #print sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
    #print 1
    time.sleep(2)
    try:
        a = sock.recv(1)
    except socket.error as (e, a):
        print errno.errorcode[e]
    print a, len(a)

    errno.ECONNREFUSED
    '''
    print 'before recv'
    try:
        print sock.recv(102)
    except socket.error as e:
        print 'in exception'
        print e
    '''