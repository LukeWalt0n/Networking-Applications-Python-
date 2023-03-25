#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import argparse
import socket
import os
import sys
import struct
import time
import random
import traceback # useful for exception handling
import threading

def setupArgumentParser() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description='A collection of Network Applications developed for SCC.203.')
        parser.set_defaults(func=ICMPPing, hostname='lancaster.ac.uk')
        subparsers = parser.add_subparsers(help='sub-command help')
        
        parser_p = subparsers.add_parser('ping', aliases=['p'], help='run ping')
        parser_p.set_defaults(timeout=4)
        parser_p.add_argument('hostname', type=str, help='host to ping towards')
        parser_p.add_argument('--count', '-c', nargs='?', type=int,
                              help='number of times to ping the host before stopping')
        parser_p.add_argument('--timeout', '-t', nargs='?',
                              type=int,
                              help='maximum timeout before considering request lost')
        parser_p.set_defaults(func=ICMPPing)

        parser_t = subparsers.add_parser('traceroute', aliases=['t'],
                                         help='run traceroute')
        parser_t.set_defaults(timeout=4, protocol='icmp')
        parser_t.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_t.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_t.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_t.set_defaults(func=Traceroute)
        
        parser_pt = subparsers.add_parser('paris-traceroute', aliases=['pt'],
                                         help='run paris-traceroute')
        parser_pt.set_defaults(timeout=4, protocol='icmp')
        parser_pt.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_pt.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_pt.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_pt.set_defaults(func=ParisTraceroute)

        parser_w = subparsers.add_parser('web', aliases=['w'], help='run web server')
        parser_w.set_defaults(port=8080)
        parser_w.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_w.set_defaults(func=WebServer)

        parser_x = subparsers.add_parser('proxy', aliases=['x'], help='run proxy')
        parser_x.set_defaults(port=8000)
        parser_x.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_x.set_defaults(func=Proxy)

        args = parser.parse_args()
        return args



##Contains useful methods we can use later
class NetworkApplication:

    def checksum(self, dataToChecksum: str) -> str:
        csum = 0
        countTo = (len(dataToChecksum) // 2) * 2
        count = 0

        while count < countTo:
            thisVal = (dataToChecksum[count+1]) * 256 + (dataToChecksum[count])
            csum = csum + thisVal
            csum = csum & 0xffffffff
            count = count + 2

        if countTo < len(dataToChecksum):
            csum = csum + dataToChecksum[len(dataToChecksum) - 1]
            csum = csum & 0xffffffff

        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)

        answer = socket.htons(answer)

        return answer

    ##To be used for results generated in T1.1
    def printOneResult(self, destinationAddress: str, packetLength: int, time: float, ttl: int, destinationHostname=''):
        if destinationHostname:
            print("%d bytes from %s (%s): ttl=%d time=%.2f ms" % (packetLength, destinationHostname, destinationAddress, ttl, time))
        else:
            print("%d bytes from %s: ttl=%d time=%.2f ms" % (packetLength, destinationAddress, ttl, time))

    ##To be used for results generated in T1.2
    def printAdditionalDetails(self, packetLoss=0.0, minimumDelay=0.0, averageDelay=0.0, maximumDelay=0.0):
        print("%.2f%% packet loss" % (packetLoss))
        if minimumDelay > 0 and averageDelay > 0 and maximumDelay > 0:
            print("rtt min/avg/max = %.2f/%.2f/%.2f ms" % (minimumDelay, averageDelay, maximumDelay))

    def printMultipleResults(self, ttl: int, destinationAddress: str, measurements: list, destinationHostname=''):
        latencies = ''
        noResponse = True
        for rtt in measurements:
            if rtt is not None:
                latencies += str(round(rtt, 3))
                latencies += ' ms  '
                noResponse = False
            else:
                latencies += '* ' 

        if noResponse is False:
            print("%d %s (%s) %s" % (ttl, destinationHostname, destinationAddress, latencies))
        else:
            print("%d %s" % (ttl, latencies))



##For Task T1.1
ICMP_ECHOREPLY = 0 # Echo reply (per RFC792)
ICMP_ECHO = 8 # Echo request (per RFC792)
ICMP_MAX_RECV = 10000 # Max size of incoming buffer

class ICMPPing(NetworkApplication):

    def receiveOnePing(self, icmpSocket, destinationAddress, ID, timeout):
       
        data = icmpSocket.recvfrom(ICMP_MAX_RECV)
        timeRecv = time.time()
        
        p = data[0]
        header = struct.unpack("BBHHH", p[20:])

        ## We calculate the size of the header using the format specifiers.
        ## "BBHHH" means it is a byte,byte,2byte,2byte,2byte = 8 bytes for the header.
        size = struct.calcsize("BBHHH")
        
        ## Check if the ID matches the header ID.
        if(ID == header[3]):
            return timeRecv, size
            
        else:
            return None, None
       
    ## Define sequence as a global so we can increment it.
    sequence =0
    def sendOnePing(self, icmpSocket : socket, destinationAddress, ID):
        ## Initialise checksum to 0.
        cs = 0
        
        header = struct.pack("BBHHH", ICMP_ECHO, 0, cs, ID, self.sequence)

        cs = self.checksum(header)
        ##Pack it again with new checksum.
        packet= struct.pack("BBHHH", ICMP_ECHO, 0, cs, ID, self.sequence)
        # 4. Send packet using socket
        try:
            icmpSocket.sendto(packet, (destinationAddress,1))
        except socket.error as e:
                print(e)

        start_time = time.time()
        return start_time
        
            

        

    def doOnePing(self, destinationAddress, timeout):
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
    
        Id = random.randint(1,100)
    
        startTime = self.sendOnePing(sock, destinationAddress, Id)
        receiveInfo = self.receiveOnePing(sock,destinationAddress,Id, startTime)
        #ReceiveOnePing returns a tuple of finalTime, and packetSize.
        finalTime = receiveInfo[0]
        packetSize = receiveInfo[1]
        self.printOneResult(destinationAddress, packetSize, (finalTime-startTime), timeout, socket.gethostbyaddr(destinationAddress))
        sock.close()
       
        return finalTime
        
        


    
    def __init__(self, args):
        print('Ping to: %s...' % (args.hostname))
        # 1. Resolve host name to IP address
        ip = socket.gethostbyname(args.hostname)
        

        # 2. Call doOnePing function, approximately every second
        for x in range(5):
            self.doOnePing(ip, args.timeout)
            time.sleep(1)
            



##For task T1.2
TRACERT_MAX_HOPS = 30 # Maximum number of hops for traceroute.
class Traceroute(NetworkApplication):


    def makePacket(self):
        checksum = 0
        ID = os.getpid() & 0xFFFF

        #Dummy header, like in ICMP ping
        header = struct.pack("BBHHH", ICMP_ECHO, 0, checksum, ID, 1) 
        #Pack some data too, just use the time.
        data = struct.pack("d",time.time())
        #Now calculate the checksum:
        finalCheckSum = self.checksum(header + data)
        #Now re-pack the information:
        finalHeader = struct.pack("BBHHH", ICMP_ECHO, 0, finalCheckSum, ID, 1)
        packet = (finalHeader + data)

        sizeOfPacket = struct.calcsize("BBHHHHd")

        return packet, sizeOfPacket






    def doTraceroute(self, destinationAddress, timeout):
        ttl = 1
        port = 33434
        times = [0,0,0]
        #Make a packet to send, only want to do this once.
        makePacketData = self.makePacket()
        packet = makePacketData[0]
        sizeOfPacket = makePacketData[1]
        
        while True:
           
            #Create our receiving socket.
            rx = socket.socket(socket.AF_INET,socket.SOCK_RAW, socket.getprotobyname('icmp'))
            rx.settimeout(timeout)
            rx.bind(('', port))

            #Create our sending socket.
            tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.getprotobyname('udp'))
            tx.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            
            #Record the time sent.
            

            finished = False
            #Set to two for the indexing into the array, 2,1,0
            tries = 0
            
            while (tries < 3):
                sendTime = time.time()
                rx.settimeout(timeout)
                tx.sendto(packet,(destinationAddress,port))
                try:
                    data, curr_addr = rx.recvfrom(512)
                except socket.timeout as e:
                    receiveTime = None

                curr_addr = curr_addr[0]
                receiveTime = time.time()
                
                if(receiveTime == None):
                    times[tries] = None
                else:
                    times[tries] = ((receiveTime-sendTime)*1000)
                
                tries += 1
                
            
            self.printMultipleResults(ttl, destinationAddress, times, socket.gethostbyname(curr_addr))
            ttl += 1

            if curr_addr == destinationAddress or ttl > TRACERT_MAX_HOPS:
                rx.close()
                tx.close()
                break
                
    
    def __init__(self, args):
        # Please ensure you print each result using the printOneResult method!
        print('Traceroute to: %s... over a maximum of 30 hops' % (args.hostname))
        ip = socket.gethostbyname(args.hostname)
        self.doTraceroute(ip, 1)
        
        
        


##For task T1.3
class ParisTraceroute(NetworkApplication):

    def makePacket(self):
        checksum = 0
        ID = os.getpid() & 0xFFFF

        #Dummy header, like in ICMP ping
        header = struct.pack("BBHHH", ICMP_ECHO, 0, checksum, ID, 1) 
        #Pack some data too, just use the time.
        data = struct.pack("d",time.time())
        #Now calculate the checksum:
        finalCheckSum = self.checksum(header + data)
        #Now re-pack the information:
        finalHeader = struct.pack("BBHHH", ICMP_ECHO, 0, finalCheckSum, ID, 1)
        packet = (finalHeader + data)

        sizeOfPacket = struct.calcsize("BBHHHHd")

        return packet, sizeOfPacket

    def doParisTraceRoute(self, destinationAddress, timeout):
        ttl = 1
        port = 33434
        times = [0,0,0]
        #Make a packet to send, only want to do this once.
        makePacketData = self.makePacket()
        packet = makePacketData[0]
        sizeOfPacket = makePacketData[1]
        
        while True:
           
            #Create our receiving socket.
            rx = socket.socket(socket.AF_INET,socket.SOCK_RAW, socket.getprotobyname('icmp'))
            rx.settimeout(timeout)
            rx.bind(('', port))

            #Create our sending socket.
            tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.getprotobyname('udp'))
            tx.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            
            #Record the time sent.
            

            finished = False
            #Set to two for the indexing into the array, 2,1,0
            tries = 0
            
            while (tries < 3):
                sendTime = time.time()
                rx.settimeout(timeout)
                tx.sendto(packet,(destinationAddress,port))
                try:
                    data, curr_addr = rx.recvfrom(512)
                except socket.timeout as e:
                    receiveTime = None

                curr_addr = curr_addr[0]
                receiveTime = time.time()
                
                if(receiveTime == None):
                    times[tries] = None
                else:
                    times[tries] = ((receiveTime-sendTime)*1000)
                
                tries += 1
                
            
            self.printMultipleResults(ttl, destinationAddress, times, socket.gethostbyname(curr_addr))
            ttl += 1

            if curr_addr == destinationAddress or ttl > TRACERT_MAX_HOPS:
                
                rx.close()
                tx.close()
                sys.exit(1)


    def __init__(self, args):
        # Please ensure you print each result using the printOneResult method!
        print('Paris-Traceroute to: %s...' % (args.hostname))
        ip = socket.gethostbyname(args.hostname)
        self.doParisTraceRoute(ip, 1)

##For task T2.1
class WebServer(NetworkApplication):

    def handleRequest(self, tcpSocket):
        # 1. Receive request message from the client on connection socket
        try:

            request = tcpSocket.recv(1024)
        
             # 2. Extract the path of the requested object from the message (second part of the HTTP header)
            
            filename = request.split()[1]
            f = open(filename[1:])


        
            # 4. Store in temporary buffer
            outputData = f.read()
            # 5. Send the correct HTTP response error
            tcpSocket.send(bytes(("HTTP/1.1 200 OK\r\n\r\n"), 'utf-8'))
            # 6. Send the content of the file to the socket
            for i in range(0, len(outputData)):
                tcpSocket.send(bytes((outputData[i]), 'utf-8'))
            tcpSocket.send(bytes(("\r\n"), 'utf-8'))

            # 7. Close the connection socket
            tcpSocket.close()
        except:
            tcpSocket.send(bytes(("HTTP/1.1 404 Not Found\r\n\r\n"), 'utf-8'))
            tcpSocket.send(bytes(("<html><head><\head><body><h1>404 Not Found</h1></body></html>"), 'utf-8'))
            tcpSocket.close()
        pass

    def __init__(self, args):
        print('Web Server starting on port: %i...' % (args.port))
       
        SERVER_HOST = '0.0.0.0'
        SERVER_PORT = 8080
                                     #IPv4 address family    #TCP
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                                        #Multiple sockets can connect to server at one time.
        serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        serverSocket.bind((SERVER_HOST,SERVER_PORT))
        
        serverSocket.listen(1)

        while True:
            #Here we wait for a client to connect to the server.
            clientConnection, clientAddress = serverSocket.accept()
            #Once connected, call handle request
            self.handleRequest(clientConnection)
        # 5. Close server socket








##For task T2.2
class Proxy(NetworkApplication):


    def doProxy(self, tcpSocket):

        
        request = tcpSocket.recv(4096).decode()
        #print(request)
        first_line = request.split()[0]
        print("First Line: ", first_line)
        #Get the url
        url = request.split()[1]    
        print("Url: ", url)

        #Get the index where the name of the site will start
        http_position = str(url).find('://')
        #Index into that position.
        if(http_position == -1):
            temp = url
        else:
            temp = url[(http_position+3):]
        

        #Find the port:
        port_position = str(temp).find(":")

        #Find end of web server:
        webServerPos = str(temp).find('/')
        if webServerPos == -1:
            webServerPos = len(temp)
        
        webServer = ""
        port = -1

        if(port_position == -1 or webServerPos < port_position):
            #Set default port.
            port = 80
            #Get webServer
            webServer = temp[:webServerPos]
            
        else:
            port = int((temp[(port_position+1):])[:webServerPos-port_position-1])
            webServer = temp[:port_position]
        
        
        ##Now set up a new connection to the destination server
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        ##Connect to the desired server and port.

        
        #print(request + "\n")
        print("GET HOST BY NAME: ", socket.gethostbyname(webServer) + "\n")
      
        try:
                
            s.connect((socket.gethostbyname(webServer), port))
            print("Connected to: ", socket.gethostbyname(webServer))
            try:
                s.send(request.encode())
                print("Sent request to server:", request.encode())
            except:
                print("Not sending request to server")

        except socket.error as ex:
            print("Not connecting to server: ", socket.gethostbyname(webServer), port)
            print(ex)
           
        while 1:
                
            #Receive the data from the server on the proxy socket.
            try:

                data = s.recv(4096)
                if(len(data) > 0):
                    print("Data Received!")
                    tcpSocket.send(data)
                else:
                    break
            except socket.error as e:
                sys.exit(1)
        if s:
            s.close()
        if tcpSocket:
            tcpSocket.close()
                
        
        

       
            
               




    def __init__(self, args):
        print('Web Proxy starting on port: %i...' % (args.port))

        SERVER_HOST = '127.0.0.1'
        SERVER_PORT = args.port

        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        serverSocket.bind((SERVER_HOST, SERVER_PORT))
        serverSocket.listen(1)

        while True:
            clientSocket, clientAddress = serverSocket.accept()
            print("-----------------------Client connected to Proxy------------------------\n")
            self.doProxy(clientSocket)


if __name__ == "__main__":
    args = setupArgumentParser()
    args.func(args)
