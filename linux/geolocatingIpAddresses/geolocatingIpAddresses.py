import os
import sys
import pygeoip

geoIpFile = "./inputs/GeoIP.dat"
loginFile = "./inputs/logins.txt"

#Validate IP file
if not os.path.exists(geoIpFile):
    sys.exit("IP File Does Not Exist: " + geoIpFile)

#Validate login file
if not os.path.exists(loginFile):
    sys.exit("Login File Does Not Exist: " + loginFile)

ipEntries = {}

#Open new context and parse login file
with open(loginFile, 'r') as file:
    for line in file:
        ipAddress = line.split()[2]

        #Add IP entries to dictionary
        if ipAddress in ipEntries:
            ipEntries[ipAddress] += 1
        else:
            ipEntries[ipAddress] = 1

#Parse Geo IP File
geoIpData = pygeoip.GeoIP(geoIpFile)

countryEntries = {}

for item in ipEntries:
    countryName = geoIpData.country_name_by_addr(item)
    print("%s is from %s and was found %d time(s)." % (item, countryName, ipEntries[item]))

    #Add country name entries to dictionary
    if countryName in countryEntries:
        countryEntries[countryName] += 1
    else:
        countryEntries[countryName] = 1

print("%d unique IP addresses were found." % len(ipEntries))

for item in countryEntries:
    print("%d unique IP address(es) were found from %s." % (countryEntries[item], item))
