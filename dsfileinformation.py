#!/usr/bin/env python
# This file is part of ntdsxtract.
#
# ntdsxtract is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ntdsxtract is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with ntdsxtract.  If not, see <http://www.gnu.org/licenses/>.

'''
@author:        Csaba Barta
@license:       GNU General Public License 2.0 or later
@contact:       csaba.barta@gmail.com
'''

import sys
from struct import *
from binascii import *
import ntds.version
from ntds.dstime import *
from ntds.lib.dump import *
import time

if len(sys.argv) < 2:
    sys.stderr.write("\nDSFileInformation v" + str(ntds.version.version))
    sys.stderr.write("\nExtracts information related to the NTDS.DIT database file")
    sys.stderr.write("\n\nusage: %s <ntds.dit>\n" % sys.argv[0])
    sys.stderr.write("\n\n  options:")
    sys.stderr.write("\n    --debug")
    sys.stderr.write("\n          Turn on detailed error messages and stack trace")
    sys.exit(1)

sys.stderr.write("\n[+] Started at: %s" % time.strftime(
                                        "%a, %d %b %Y %H:%M:%S UTC",
                                        time.gmtime()))

f = open(sys.argv[1], "rb", 0)
header = f.read(8192)

(pagesize, ) = unpack('I', header[236:240])
(wmajorversion, ) = unpack('I', header[216:220])
(wminorversion, ) = unpack('I', header[220:224])
(wbuildnumber, )  = unpack('I', header[224:228])
(wservicepack, )  = unpack('I', header[228:232])

print "Header checksum:     %s" % hexlify(header[:4][::-1])
print "Signature:           %s" % hexlify(header[4:8][::-1])
print "File format version: %s" % hexlify(header[8:12][::-1])
print "File type:           %s" % hexlify(header[12:16][::-1])
print "Page size:           %d bytes" % pagesize
print "DB time:             %s" % hexlify(header[16:24][::-1])
print "Windows version:     %d.%d (%d) Service pack %d" % (
                                                       wmajorversion,
                                                       wminorversion,
                                                       wbuildnumber,
                                                       wservicepack
                                                       )
print "Creation time: %04d.%02d.%02d %02d:%02d:%02d" % dsGetDBLogTimeStampStr(header[24:52][4:12])
print "Attach time:   %04d.%02d.%02d %02d:%02d:%02d" % dsGetDBLogTimeStampStr(header[72:80])
if unpack("B", header[88:96][:1]) == (0, ):
    print "Detach time:   database is in dirty state"
else:
    print "Detach time:   %04d.%02d.%02d %02d:%02d:%02d" % dsGetDBLogTimeStampStr(header[88:96])
print "Consistent time: %04d.%02d.%02d %02d:%02d:%02d" % dsGetDBLogTimeStampStr(header[64:72])
print "Recovery time:   %04d.%02d.%02d %02d:%02d:%02d" % dsGetDBLogTimeStampStr(header[244:252])
print "Header dump (first 672 bytes):"
print dump(header[:672], 16, 4)
f.close()
