#!/usr/bin/python
"""
Searches the binary file produced by generate-keys.py for any of the SSID
fragments provided on the command line

Test networks: SpeedTouchF8A3D0 BTHomeHub-8DF3
               742DA831D2       06F48A28EB
"""
import sys
import re
import subprocess

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



if len(sys.argv) != 2:
	print """ Usage: %s SSID""" % sys.argv[0]
	sys.exit(0)

ssid_list = []
ssid_input_list = sys.argv[1:]
for ssid in ssid_input_list:
	m = re.search("([0-9A-F]{6})$", ssid)
	if m:
		ssid_list += m.groups()
	else:
		m = re.search("([0-9A-F]{4})$", ssid)
		if m:
			ssid_list += m.groups()
		else:
			print >> sys.stderr, "Ignoring '%s' because it doesn't end in 4 or 6 hexadecimal uppercase characters" % ssid

if len(ssid_list) == 0: sys.exit()
print >> sys.stderr, "Will search for keys matching", ssid_list

for ssid in ssid_list:
	subprocess.Popen("pv keys/xxxx%s | xxd -ps -c8 -u | grep ^%s | cut -b7-" % 
			(ssid[4:6], ssid[:4]), shell=True).communicate()

