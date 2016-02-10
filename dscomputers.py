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
import re
from binascii import *
from ntds.version import *
from ntds.dsdatabase import *
from ntds.dsrecord import *
from ntds.dsobjects import *
from ntds.dstime import *
from ntds.lib.dump import *
import time
from ntds.lib.fs import *
from ntds.lib.hashoutput import *
from ntds.lib.csvoutput import *

def usage():
    sys.stderr.write("\nDSComputers v" + str(ntds.version.version))
    sys.stderr.write("\nExtracts information related to computer objects")
    sys.stderr.write("\n\nusage: %s <datatable> <work directory> [option]" % sys.argv[0])
    sys.stderr.write("\n\n  datatable")
    sys.stderr.write("\n    The path to the file called datatable extracted by esedbexport")
    sys.stderr.write("\n  work directory")
    sys.stderr.write("\n    The path to the directory where ntdsxtract should store its")
    sys.stderr.write("\n    cache files and output files. If the directory does not exist")
    sys.stderr.write("\n    it will be created.")
    sys.stderr.write("\n  options:")
    sys.stderr.write("\n    --name <computer name regexp>")
    sys.stderr.write("\n          List computers identified by the regular expression")
    sys.stderr.write("\n    --syshive <path to system hive>")
    sys.stderr.write("\n          Required for password hash, history and supplemental credentials extraction")
    sys.stderr.write("\n          This option should be specified before the password hash")
    sys.stderr.write("\n          and password history extraction options!")
    sys.stderr.write("\n    --lmoutfile <path to the LM hash output file>")
    sys.stderr.write("\n    --ntoutfile <path to the NT hash output file>")
    sys.stderr.write("\n    --pwdformat <format of the hash output>")
    sys.stderr.write("\n          ophc - OphCrack format")
    sys.stderr.write("\n                 When this format is specified the NT output file will be used")
    sys.stderr.write("\n          john - John The Ripper format")
    sys.stderr.write("\n    --passwordhashes")
    sys.stderr.write("\n    --passwordhistory")
    sys.stderr.write("\n    --supplcreds")
    sys.stderr.write("\n    --bitlocker")
    sys.stderr.write("\n          Extract Bitlocker recovery information (recovery password)")
    sys.stderr.write("\n    --csvoutfile <name of the CSV output file>")
    sys.stderr.write("\n          The filename of the csv file to which ntdsxtract should write the")
    sys.stderr.write("\n          output")
    sys.stderr.write("\n    --debug")
    sys.stderr.write("\n          Turn on detailed error messages and stack trace")
    sys.stderr.write("\n")
    sys.stderr.flush()

def processComputer(computer):
    global csvoutfile
    global pwdump
    global pwdformat
    global pwhdump
    global bitldump
    global suppcreddump

    sys.stdout.write(str(computer))
    
    # The main computer record
    if csvoutfile != "":
        write_csv([computer.RecordId, computer.Name, computer.DNSHostName, str(computer.GUID),
                str(computer.SID), computer.OSName, computer.OSVersion,
                "=\"" + dsGetDSTimeStampStr(computer.WhenCreated) + "\"", "=\"" + dsGetDSTimeStampStr(computer.WhenChanged) + "\"",
                "", "", "", "", "", "", str(computer.DialInAccessPermission)
                ])
    
    if pwdump == True:
        sys.stdout.write("\nPassword hashes:")
        (lm, nt) = computer.getPasswordHashes()
        if nt != '':
            if pwdformat == 'john':
                sys.stdout.write("\n\t" + format_john(computer.Name,computer.SID,nt,'NT'))
                ntof.writelines(format_john(computer.Name, computer.SID, nt, 'NT') + "\n")
            if lm != '':
                if pwdformat == 'john':
                    sys.stdout.write("\n\t" + format_john(computer.Name,computer.SID,lm,'LM'))
                    lmof.writelines(format_john(computer.Name, computer.SID, lm, 'LM') + "\n")
                if pwdformat == 'ophc':
                    sys.stdout.write("\n\t" + format_ophc(computer.Name,computer.SID, lm, nt))
                    ntof.writelines(format_ophc(computer.Name,computer.SID, lm, nt) + "\n")
    
    if pwhdump == True:
        sys.stdout.write("\nPassword history:")
        lmhistory = None
        nthistory = None
        (lmhistory, nthistory) = computer.getPasswordHistory()
        if nthistory != None:
            if pwdformat == 'john':
                hashid = 0
                for nthash in nthistory:
                    sys.stdout.write("\n\t" + format_john(computer.Name + "_nthistory" + str(hashid),computer.SID, nthash, 'NT'))
                    ntof.writelines(format_john(computer.Name + "_nthistory" + str(hashid), nthash,computer.SID, 'NT') + "\n")
                    hashid += 1
                if lmhistory != None:
                    hashid = 0
                    for lmhash in lmhistory:
                        sys.stdout.write("\n\t" + format_john(computer.Name + "_lmhistory" + str(hashid),computer.SID, lmhash, 'LM'))
                        lmof.writelines(format_john(computer.Name + "_lmhistory" + str(hashid),computer.SID, lmhash, 'LM') + "\n")
                        hashid += 1
            if pwdformat == 'ophc':
                if lmhistory != None:
                    for hashid in range(0,len(lmhistory)):
                        sys.stdout.write("\n\t" + format_ophc(computer.Name + "_history" + str(hashid),computer.SID, lmhistory[hashid], nthistory[hashid]))
                        ntof.writelines(format_ophc(computer.Name + "_history" + str(hashid), computer.SID, lmhistory[hashid], nthistory[hashid]) + "\n")

    if bitldump == True:
        sys.stdout.write("\nRecovery information:")
        for rinfo in computer.getRecoveryInformations(db):
            sys.stdout.write("\n\t" + rinfo.Name)
            sys.stdout.write("\n\tRecovery GUID: " + str(rinfo.RecoveryGUID))
            sys.stdout.write("\n\tVolume GUID:   " + str(rinfo.VolumeGUID))
            sys.stdout.write("\n\tWhen created: " + dsGetDSTimeStampStr(rinfo.WhenCreated))
            sys.stdout.write("\n\tWhen changed: " + dsGetDSTimeStampStr(rinfo.WhenChanged))
            sys.stdout.write("\n\tRecovery password: " + rinfo.RecoveryPassword)
            sys.stdout.write("\n\tFVE Key package:\n" + dump(unhexlify(rinfo.FVEKeyPackage),16, 16))
            sys.stdout.write("\n\n")
            
            if csvoutfile != "":
                write_csv([computer.RecordId, computer.Name, computer.DNSHostName, str(computer.GUID),
                    str(computer.SID), computer.OSName, computer.OSVersion,
                    "=\"" + dsGetDSTimeStampStr(computer.WhenCreated) + "\"", "=\"" + dsGetDSTimeStampStr(computer.WhenChanged) + "\"",
                    rinfo.Name, str(rinfo.RecoveryGUID), str(rinfo.VolumeGUID), "=\"" + dsGetDSTimeStampStr(rinfo.WhenCreated) + "\"",
                    "=\"" +dsGetDSTimeStampStr(rinfo.WhenChanged) + "\"", rinfo.RecoveryPassword
                    ])

    if suppcreddump == True:
        creds = None
        creds = computer.getSupplementalCredentials()
        if creds != None:
            sys.stdout.write("\nSupplemental credentials:\n")
            creds.Print("  ")

    sys.stdout.write("\n")
    sys.stdout.flush()

if len(sys.argv) < 3:
    usage()
    sys.exit(1)

syshive = ""
ntoutfile = ""
lmoutfile = ""
csvoutfile = ""
pwdformat = ""
pwdump = False
pwhdump = False
bitldump = False
suppcreddump = False
optid = 0
ntof = None
lmof = None
csvof = None
reName = None

sys.stderr.write("\n[+] Started at: %s" % time.strftime(
                                        "%a, %d %b %Y %H:%M:%S UTC",
                                        time.gmtime()))
sys.stderr.write("\n[+] Started with options:")
for opt in sys.argv:
    if opt == "--name":
        if len(sys.argv) < optid + 2:
            usage()
            sys.exit(1)
        name = sys.argv[optid + 1]
        reName = re.compile(name)
        sys.stderr.write("\n\t[-] Computer name: %s" % name)
    if opt == "--syshive":
        if len(sys.argv) < optid + 2:
            usage()
            sys.exit(1)
        syshive = sys.argv[optid + 1]
    if opt == "--passwordhashes":
        pwdump = True
        sys.stderr.write("\n\t[-] Extracting password hashes")
    if opt == "--passwordhistory":
        pwhdump = True
        sys.stderr.write("\n\t[-] Extracting password history")
    if opt == "--supplcreds":
        suppcreddump = True
        sys.stderr.write("\n\t[-] Extracting supplemental credentials")
    if opt == "--bitlocker":
        bitldump = True
        sys.stderr.write("\n\t[-] Extracting BitLocker recovery information")
    if opt == "--lmoutfile":
        if len(sys.argv) < optid + 2:
            usage()
            sys.exit(1)
        lmoutfile = sys.argv[optid + 1]
        sys.stderr.write("\n\t[-] LM hash output filename: " + sys.argv[optid + 1])
    if opt == "--ntoutfile":
        if len(sys.argv) < optid + 2:
            usage()
            sys.exit(1)
        ntoutfile = sys.argv[optid + 1]
        sys.stderr.write("\n\t[-] NT hash output filename: " + sys.argv[optid + 1])
    if opt == "--pwdformat":
        if len(sys.argv) < optid + 2:
            usage()
            sys.exit(1)
        pwdformat = sys.argv[optid + 1]
        sys.stderr.write("\n\t[-] Hash output format: " + sys.argv[optid + 1])
    if opt == "--csvoutfile":
        if len(sys.argv) < optid + 2:
            usage()
            sys.exit(1)
        csvoutfile = sys.argv[optid + 1]
        sys.stderr.write("\n\t[-] CSV output filename: " + sys.argv[optid + 1])
    optid += 1

# Setting up the environment
if not checkfile(sys.argv[1]):
    sys.stderr.write("\n[!] Error! datatable cannot be found!\n")
    sys.exit(1)
wd = ensure_dir(sys.argv[2])

if pwdump or pwhdump or suppcreddump:
    if syshive == "":
        sys.stderr.write("\n[!] Error! Missing path to system hive! Use --syshive option.\n")
        sys.stderr.flush()
        usage()
        sys.exit(1)

if pwdump == True or pwhdump == True:
    if pwdformat == "":
        sys.stderr.write("\n[!] Error! Missing password hash output format! Use --pwdformat option.\n")
        sys.stderr.flush()
        sys.exit(1)
    if ntoutfile == "":
        sys.stderr.write("\n[!] Error! Missing password hash output file! Use --ntoutfile option.\n")
        sys.stderr.flush()
        sys.exit(1)
    if pwdformat == "john" and lmoutfile == "":
        sys.stderr.write("\n[!] Error! Missing LM hash output file! Use --lmoutfile option.\n")
        sys.stderr.flush()
        sys.exit(1)

if csvoutfile != "":
    init_csv(path.join(wd, csvoutfile))
    
if pwdump == True or pwhdump == True:
    ntof = open(path.join(wd, ntoutfile), 'a')
    if pwdformat == 'john':
        lmof = open(path.join(wd, lmoutfile), 'a')

db = dsInitDatabase(sys.argv[1], wd)

if pwdump == True or pwhdump == True or suppcreddump == True:
    dsInitEncryption(syshive)
        
if csvoutfile != "":
    write_csv(["Record ID", "Computer name", "DNS name", "GUID",
            "SID", "OS name", "OS version", "When created", "When changed",
            "Bitlocker recovery name", "Bitlocker recovery GUID",
            "Bitlocker volume GUID", "Bitlocker when created",
            "Bitlocker when changed", "Bitlocker recovery password", "Dial-In Permission"
            ])

sys.stdout.write("\n\nList of computers:")
sys.stdout.write("\n==================")
for recordid in dsMapRecordIdByTypeId[dsGetTypeIdByTypeName(db, "Computer")]:
    computer = None
    try:
        computer = dsComputer(db, recordid)
    except KeyboardInterrupt:
        raise KeyboardInterrupt
    except:
        sys.stderr.write("\n[!] Unable to instantiate user object (record id: %d)" % recordid)
        continue
    if reName != None and not reName.search(computer.Name):
        computer = None
        continue

    processComputer(computer)

if csvoutfile != "":
    close_csv()

if ntof != None:
    ntof.close()
if lmof != None:
    lmof.close()

