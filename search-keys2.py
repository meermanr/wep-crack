#!/usr/bin/env python
"""
Query key database for possible encryption keys, given an SSID.

Keys files are named after SSIDs. The content of each file is made up of 8 byte 
records, each of which is composed of three bytes of SSID, then 5 bytes of 
encryption key.
"""

import struct
import mmap

# ----------------------------------------------------------------------------
def hex2bin(rHex):
    # Convert hexadecimal representation into a binary string
    iValue = int(rHex, 16)
    rBinary = struct.pack(">I", iValue)

    iLength = len(rHex)/2
    rBinary = rBinary[-iLength:]

    return rBinary

# ----------------------------------------------------------------------------
def bin2hex(rBin):
    return "".join(("%02X" % ord(x)) for x in rBin)

# ----------------------------------------------------------------------------
def extract_keys(rSSID):
    """
    :Parameters:
        rSSID : str
            Hexadecimal representation of the SSID to find encryption keys.

    :Returns:
        Generator which yields encryption key strings, such as "AABBCCDDEEFF"
    """
    rSSID = rSSID.upper()
    rFile = "keys/xxxx%s" % rSSID[-2:]

    if len(rSSID) == 6:
        sCodec = struct.Struct("3s5s")
    elif len(rSSID) == 4:
        sCodec = struct.Struct("x2s5s")
    else:
        assert False, "SSID must exactly 4 or 6 characters"

    iRecordSize = sCodec.size
    rSSID_binary = hex2bin(rSSID)

    with file(rFile, "rb") as sFH:
        sFH.seek(0, 2)  # End of file
        iFileLength = sFH.tell()
        sFH.seek(0, 0)  # Start of file

        iFH = sFH.fileno()
        sMMap = mmap.mmap(iFH, 0, mmap.MAP_SHARED, mmap.PROT_READ)

        iOffset = 0
        while iOffset < iFileLength:
            (rNetwork, rKey) = sCodec.unpack_from(sMMap, iOffset)
            iOffset += iRecordSize

            if rNetwork != rSSID_binary:
                continue

            rKey = bin2hex(rKey)
            yield rKey

# -----------------------------------------------------------------------------
def extract_SSID(rNetworkName):
    import re
    rNetworkName = rNetworkName.upper()
    sMatch = re.search(r"[0-9A-F]{4,6}$", rNetworkName)
    if sMatch:
        rMatch = sMatch.group(0)
        print rMatch
        assert len(rMatch) in [4,6], "SSID must be exactly 4 or 6 characters"
        return rMatch

# -----------------------------------------------------------------------------
def find_keys_for_network(rNetworkName):
    rSSID = extract_SSID(rNetworkName)
    siKeys = extract_keys(rSSID)
    return siKeys

# =============================================================================
if __name__ == "__main__":
    import sys
    assert len(sys.argv) == 2, ("This script requires exactly one argument: "
            " the network name to find keys for")

    rNetworkName = sys.argv[1]
    siKeys = find_keys_for_network(rNetworkName)
    for rKey in siKeys:
        print rKey
