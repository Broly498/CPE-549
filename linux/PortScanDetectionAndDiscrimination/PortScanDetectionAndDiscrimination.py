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

#Open new context and parse PCAP file
with open(inputFile, 'rb') as fileObject:
    pcapObject = dpkt.pcap.Reader(fileObject)

    tcpPacketsByTimeStamp = {}
    udpPacketsByTimeStamp = {}

    nullScanDestinationPorts = []
    xmasScanDestinationPorts = []
    udpScanDestinationPorts = []
    connectScanDestinationPorts = []
    halfOpenScanDestinationPorts = []

    #Extract Ethernet Packets
    for ts, buffer in pcapObject:
        ethernetPacket = dpkt.ethernet.Ethernet(buffer)

        #Extract IP Packets
        if ethernetPacket.type == dpkt.ethernet.ETH_TYPE_IP:
            ipPacket = ethernetPacket.data

            #Extract UDP Packets
            if ipPacket.p == dpkt.ip.IP_PROTO_UDP:
                udpPacketsByTimeStamp[ts] = ipPacket

            #Extract TCP Packets
            if ipPacket.p == dpkt.ip.IP_PROTO_TCP:
                tcpPacketsByTimeStamp[ts] = ipPacket

                packetData = ipPacket.data
                destinationPort = packetData.dport

                #Flag the Destination Port of the Mallicious Null Scan Source
                if (packetData.flags == 0) and (destinationPort not in nullScanDestinationPorts):
                    nullScanDestinationPorts.append(destinationPort)

                #Flag the Destination Port of the Mallicious Xmas Scan Source
                elif ((packetData.flags & dpkt.tcp.TH_FIN) != 0) and \
                     ((packetData.flags & dpkt.tcp.TH_URG) != 0) and \
                     ((packetData.flags & dpkt.tcp.TH_PUSH) != 0) and \
                     (destinationPort not in xmasScanDestinationPorts):
                    xmasScanDestinationPorts.append(destinationPort)

    #Define Scan Heuristic for the Following Scans: UDP, Connect, Half-Open

    scanPacketCount = 10
    scanTimeWindow_s = 1.
    scanThresholdFrequency_Hz = scanPacketCount / scanTimeWindow_s

    #Check if any UDP Packets Are Present
    if udpPacketsByTimeStamp:
        timer_s = 0.

        #The Start Time is that of the First UDP Packet
        startTime_s = list(udpPacketsByTimeStamp.keys())[0]

        udpPacketCountBySource = {}

        udpScanSources = []

        #Find Potential UDP Scan Sources
        for currentTime_s in udpPacketsByTimeStamp:
            #Update the Timer
            timer_s = currentTime_s - startTime_s

            udpPacket = udpPacketsByTimeStamp[currentTime_s]
            source = udpPacket.src

            #Only Look at Packets that Contain Only the Header Information
            if len(udpPacket.data) == 8:
                #Ensure that Every Source Count Starts at Zero
                if source not in udpPacketCountBySource:
                    udpPacketCountBySource[source] = 0

                #Update the Packet Frequency
                udpFrequency_Hz = udpPacketCountBySource[source] / scanTimeWindow_s

                #Flag the Source if the Scan Threshold Has Been Exceeded
                if (udpFrequency_Hz > scanThresholdFrequency_Hz) and (source not in udpScanSources):
                    udpScanSources.append(source)
                #The Scan Time Window Has Been Exceeded, Reset the Timer and Source Count
                elif timer_s > scanTimeWindow_s:
                    timer_s = 0.
                    udpPacketCountBySource[source] = 0
                #The Time Window and Scan Threshold Has Not Been Exceeded, Increment the Source Count
                else:
                    udpPacketCountBySource[source] += 1

        #Find Unique UDP Scan Port Destinations
        for currentTime_s in udpPacketsByTimeStamp:
            udpPacket = udpPacketsByTimeStamp[currentTime_s]
            source = udpPacket.src

            packetData = udpPacket.data
            destinationPort = packetData.dport

            #Flag the Destination Port
            if (source in udpScanSources) and (destinationPort not in udpScanDestinationPorts):
                udpScanDestinationPorts.append(destinationPort)

    #Check if any TCP Packets Are Present
    if tcpPacketsByTimeStamp:
        timer_s = 0.

        #The Start Time is that of the First TCP Packet
        startTime_s = list(tcpPacketsByTimeStamp.keys())[0]

        tcpSynPacketCountBySource = {}

        tcpSynPacketSources = []
        tcpSynPacketPortDestinations = []

        #Find Potential Scan Sources (Syn Flag): Connect and Half-Open
        for currentTime_s in tcpPacketsByTimeStamp:
            #Update the Timer
            timer_s = currentTime_s - startTime_s

            tcpPacket = tcpPacketsByTimeStamp[currentTime_s]
            packetData = tcpPacket.data

            source = tcpPacket.src
            portDestination = packetData.dport
    
            #Ensure that Every Source Count Starts at Zero
            if source not in tcpSynPacketCountBySource:
                tcpSynPacketCountBySource[source] = 0

            #Update the Packet Frequency
            tcpFrequency_Hz = tcpSynPacketCountBySource[source] / scanTimeWindow_s

            #Flag the Source and Destination Port if the Scan Threshold Has Been Exceeded
            if tcpFrequency_Hz > scanThresholdFrequency_Hz:
                if source not in tcpSynPacketSources:
                    tcpSynPacketSources.append(source)

                if portDestination not in tcpSynPacketPortDestinations:
                    tcpSynPacketPortDestinations.append(portDestination)
            #The Scan Time Window Has Been Exceeded, Reset the Timer and Source Count
            elif timer_s > scanTimeWindow_s:
                timer_s = 0.
                tcpSynPacketCountBySource[source] = 0
            #The Packet Contains a Syn Flag, Increment the Source Count
            elif packetData.flags == dpkt.tcp.TH_SYN:
                tcpSynPacketCountBySource[source] += 1
        
        tcpSynAckPacketPortSources = []

        #Find Potential Scan Responses (Syn/Ack Flags): Connect and Half-Open
        for currentTime_s in tcpPacketsByTimeStamp:
            packet = tcpPacketsByTimeStamp[currentTime_s]
            packetData = packet.data

            sourcePort = packetData.sport
            destination = packet.dst

            #Flag the Source and Destination if the Packet Contains Syn/Ack Flags
            #and it is Responding to a Potential Scan Source
            if ((packetData.flags & dpkt.tcp.TH_SYN) != 0) and \
               ((packetData.flags & dpkt.tcp.TH_ACK) != 0) and \
               (destination in tcpSynPacketSources) and \
               (sourcePort in tcpSynPacketPortDestinations) and \
               (sourcePort not in tcpSynAckPacketPortSources):
                tcpSynAckPacketPortSources.append(sourcePort)

        tcpAckPacketPortSources = []
        tcpRstPacketPortSources = []

        #Find Potential Scan Completions (Ack, Rst Flags): Connect and Half-Open
        for currentTime_s in tcpPacketsByTimeStamp:
            packet = tcpPacketsByTimeStamp[currentTime_s]
            packetData = packet.data

            source = packet.src
            sourcePort = packetData.sport
            destinationPort = packetData.dport

            #Check if the Source and Destination Have Been
            #Part of a Potential Half-Open or Connect Scan Handshake
            if (destinationPort in tcpSynPacketPortDestinations) and \
               (destinationPort in tcpSynAckPacketPortSources) and \
               (source in tcpSynPacketSources):

                #Flag the Source as a Connect Scan if it Contains an Ack Flag 
                if (packetData.flags == 16) and (sourcePort not in tcpAckPacketPortSources):
                    tcpAckPacketPortSources.append(sourcePort)
                #Flag the Source as a Half-Open Scan if it Contains a Rst Flag
                if packetData.flags == 4 and (sourcePort not in tcpRstPacketPortSources):
                    tcpRstPacketPortSources.append(sourcePort)

        halfOpenScanSources = []
        connectScanSources = []

        #Find Confirmed Scan Sources: Connect and Half-Open 
        for currentTime_s in tcpPacketsByTimeStamp:
            packet = tcpPacketsByTimeStamp[currentTime_s]
            packetData = packet.data

            source = packet.src
            sourcePort = packetData.sport
            destinationPort = packetData.dport

            #Check if the Source and Destination Port Has Been Flagged: Connect and Half-Open
            if (source in tcpSynPacketSources) and \
               (destinationPort in tcpSynPacketPortDestinations) and \
               (destinationPort in tcpSynAckPacketPortSources):

                #Flag the Source as a Half-Open Scan
                if (sourcePort in tcpRstPacketPortSources) and \
                    (source not in halfOpenScanSources):
                    halfOpenScanSources.append(source)

                #Flag the Source as a Connect Scan
                if (sourcePort in tcpAckPacketPortSources) and \
                    (source not in connectScanSources):
                    connectScanSources.append(source)

        #Find Unique Scan Port Destinations: Connect and Half-Open
        for currentTime_s in tcpPacketsByTimeStamp:
            packet = tcpPacketsByTimeStamp[currentTime_s]
            packetData = packet.data

            source = packet.src
            destinationPort = packetData.dport

            #Flag the Half-Open Scan Destination Port
            if (source in halfOpenScanSources) and \
                (destinationPort not in halfOpenScanDestinationPorts):
                halfOpenScanDestinationPorts.append(destinationPort)

            #Flag the Connect Scan Destination Port
            if (source in connectScanSources) and \
                (destinationPort not in connectScanDestinationPorts):
                connectScanDestinationPorts.append(destinationPort)

    print("Null: %d" % len(nullScanDestinationPorts))
    print("XMAS: %d" % len(xmasScanDestinationPorts))
    print("UDP: %d" % len(udpScanDestinationPorts))
    print("Half-open: %d" % len(halfOpenScanDestinationPorts))
    print("Connect: %d" % len(connectScanDestinationPorts))