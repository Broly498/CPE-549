import os
import sys
import dpkt

expectedArguments = ['-i', '<inputFilename>']

#The first argument is always the name of the script
#that is being called; therefore, ignore the first one.
parsedArguments = sys.argv[1:]

#Ensure that the number of parsed arguments
#is equal to the number of expected arguments.

numberOfParsedArguments = len(parsedArguments)

if (numberOfParsedArguments) is not len(expectedArguments):
    print("Invalid Number of Command-Line Arguments Were Specified: %d" % (numberOfParsedArguments))
    print("\nExpected Command-Line Arguments:", " ", end='')
    for item in expectedArguments:
        print(item, " ", end='')
    sys.exit("\nTerminating Program.")

#The input file is the second parsed argument.
inputFile = parsedArguments[1]

#Validate input file
if not os.path.exists(inputFile):
    sys.exit("Input file was not found: " + inputFile)

#Open Input File and create PCAP object.
fileObject = open(inputFile, 'rb')

#Open new context and parse PCAP file
with open(inputFile, 'rb') as file:
    pcapObject = dpkt.pcap.Reader(fileObject)

tcpPackets = {}
udpPackets = {}
nullScanPackets = {}
xmasScanPackets = {}

#Extract Ethernet Packets
for ts, buffer in pcapObject:
    ethernetPacket = dpkt.ethernet.Ethernet(buffer)

    #Extract IP Packets
    if ethernetPacket.type == dpkt.ethernet.ETH_TYPE_IP:

        #Extrackt IP Packet Information
        ipPacket = ethernetPacket.data

        #Extract UDP Packets For UDP Scan Detection
        if ipPacket.p == dpkt.ip.IP_PROTO_UDP:
            udpPackets[ts] = ipPacket

        #Extrackt TCP Packets For Xmas Scan, Null Scan, Half-Open Scan, and Open Scan Scan Detection
        if ipPacket.p == dpkt.ip.IP_PROTO_TCP:
            tcpPackets[ts] = ipPacket

            #Detect Mallicious Null Scan Packets
            if (ipPacket.data.flags == 0):
                nullScanPackets[ts] = ipPacket
            #Detect Mallicious Xmas Scan Packets
            elif ((ipPacket.data.flags & dpkt.tcp.TH_FIN) != 0 and (ipPacket.data.flags & dpkt.tcp.TH_URG) != 0 and (ipPacket.data.flags & dpkt.tcp.TH_PUSH) != 0):
                xmasScanPackets[ts] = ipPacket

nullScanDestinationPorts = []

#Extract Null Scan Destination Ports
for key in nullScanPackets:
    packetData = nullScanPackets[key].data

    #Extract Destination Port
    destinationPort = packetData.dport
    nullScanDestinationPorts.append(destinationPort)

#Find Unique Ports That Were Scanned During the Null Scan
uniqueNullScanDestinationPorts = list(set(nullScanDestinationPorts))

xmasScanDestinationPorts = []

#Extract Xmas Scan Destination Ports
for key in xmasScanPackets:
    packetData = xmasScanPackets[key].data

    #Extract Destination Port
    destinationPort = packetData.dport
    xmasScanDestinationPorts.append(destinationPort)

#Find Unique Ports That Were Scanned During the Xmas Scan
uniqueXmasScanDestinationPorts = list(set(xmasScanDestinationPorts))

udpScanPackets = {}

if bool(udpPackets):
    timer_s = 0.
    startTime_s = list(udpPackets.keys())[0]

    maxUdpPacketsPerTimeWindow = 5
    udpPacketTimeWindow_s = 10.

    udpCountBySource = {}

    for key in udpPackets:
        currentTime_s = key

        timer_s = currentTime_s - startTime_s

        packet = udpPackets[key]
        source = packet.src
    
        if source not in udpCountBySource:
            udpCountBySource[source] = 0

        if udpCountBySource[source] > maxUdpPacketsPerTimeWindow and timer_s < udpPacketTimeWindow_s:
             udpScanPackets[key] = packet
        elif timer_s > udpPacketTimeWindow_s:
            timer_s = 0
            udpCountBySource[source] = 0
        else:
            udpCountBySource[source] += 1

udpScanDestinationPorts = []

#Extract UDP Scan Destination Ports
for key in udpScanPackets:
    packetData = udpScanPackets[key].data

    #Extract Destination Port
    destinationPort = packetData.dport
    udpScanDestinationPorts.append(destinationPort)

#Find Unique Ports That Were Scanned During the UDP Scan
uniqueUdpScanDestinationPorts = list(set(udpScanDestinationPorts))

print("Null: %d" % len(uniqueNullScanDestinationPorts))
print("XMAS: %d" % len(uniqueXmasScanDestinationPorts))
print("UDP: %d" % len(uniqueUdpScanDestinationPorts))