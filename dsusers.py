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
from os import path
import re
from ntds.version import *
from ntds.dsdatabase import *
from ntds.dsrecord import *
from ntds.dslink import *
from ntds.dstime import *
from ntds.dsobjects import *
from ntds.lib.dump import *
from ntds.lib.fs import *
from ntds.lib.hashoutput import *
from ntds.lib.csvoutput import *

def usage():
    sys.stderr.write("\nDSUsers v" + str(ntds.version.version))
    sys.stderr.write("\nExtracts information related to user objects")
    sys.stderr.write("\n\nusage: %s <datatable> <linktable> <work directory> [option]" % sys.argv[0])
    sys.stderr.write("\n\n  datatable")
    sys.stderr.write("\n    The path to the file called datatable extracted by esedbexport")
    sys.stderr.write("\n  linktable")
    sys.stderr.write("\n    The path to the file called linktable extracted by esedbexport")
    sys.stderr.write("\n  work directory")
    sys.stderr.write("\n    The path to the directory where ntdsxtract should store its")
    sys.stderr.write("\n    cache files and output files. If the directory does not exist")
    sys.stderr.write("\n    it will be created.")
    sys.stderr.write("\n\n  options:")
    sys.stderr.write("\n    --sid <user sid>")
    sys.stderr.write("\n          List user identified by SID")
    sys.stderr.write("\n    --guid <user guid>")
    sys.stderr.write("\n          List user identified by GUID")
    sys.stderr.write("\n    --name <user name regexp>")
    sys.stderr.write("\n          List user identified by the regular expression")
    sys.stderr.write("\n    --active")
    sys.stderr.write("\n          List only active accounts. This option cannot be used")
    sys.stderr.write("\n          with --flags.")
    sys.stderr.write("\n    --locked")
    sys.stderr.write("\n          List only locked accounts. This option cannot be used")
    sys.stderr.write("\n          with --flags.")
    sys.stderr.write("\n    --uac <UserAccountControl flag combination as hex>")
    sys.stderr.write("\n          List only the accounts that have the specified UAC flag")
    sys.stderr.write("\n          combination. This option cannot be used with --active or")
    sys.stderr.write("\n          --locked")
    sys.stderr.write("\n    --syshive <path to system hive>")
    sys.stderr.write("\n          Required for password hash and history extraction")
    sys.stderr.write("\n          This option should be specified before the password hash")
    sys.stderr.write("\n          and password history extraction options!")
    sys.stderr.write("\n    --lmoutfile <name of the LM hash output file>")
    sys.stderr.write("\n    --ntoutfile <name of the NT hash output file>")
    sys.stderr.write("\n    --pwdformat <format of the hash output>")
    sys.stderr.write("\n          ophc - OphCrack format")
    sys.stderr.write("\n                 When this format is specified the NT output file will be used")
    sys.stderr.write("\n          john - John The Ripper format")
    sys.stderr.write("\n          ocl  - oclHashcat format")
    sys.stderr.write("\n                 When this format is specified the NT output file will be used")
    sys.stderr.write("\n    --passwordhashes")
    sys.stderr.write("\n          Extract password hashes")
    sys.stderr.write("\n    --passwordhistory")
    sys.stderr.write("\n          Extract password history")
    sys.stderr.write("\n    --certificates")
    sys.stderr.write("\n          Extract certificates")
    sys.stderr.write("\n    --supplcreds")
    sys.stderr.write("\n          Extract supplemental credentials (e.g.: clear text passwords,")
    sys.stderr.write("\n          kerberos keys)")
    sys.stderr.write("\n    --membership")
    sys.stderr.write("\n          List groups of which the user is a member")
    sys.stderr.write("\n    --csvoutfile <name of the CSV output file>")
    sys.stderr.write("\n          The filename of the csv file to which ntdsxtract should write the")
    sys.stderr.write("\n          output")
    sys.stderr.write("\n    --debug")
    sys.stderr.write("\n          Turn on detailed error messages and stack trace")
    sys.stderr.write("\n")
    
def processUser(user):
    sys.stdout.write(str(user))
    sys.stdout.flush()

    str_anc = ""
    str_uac = ""
    if csvoutfile != "":
        for uac in user.getUserAccountControl():
            str_uac = str_uac + uac + "|"
    for ancestor in user.getAncestors(db):
            str_anc = str_anc + ancestor.Name + "|"

    if csvoutfile != "":
        write_csv([user.RecordId, user.Name, user.PrincipalName, user.SAMAccountName,
               user.getSAMAccountType(), str(user.GUID), str(user.SID),
               dsGetDSTimeStampStr(user.WhenCreated), dsGetDSTimeStampStr(user.WhenChanged),
               dsGetDSTimeStampStr(user.AccountExpires), dsGetDSTimeStampStr(user.PasswordLastSet),
               dsGetDSTimeStampStr(user.LastLogon), dsGetDSTimeStampStr(user.LastLogonTimeStamp),
               dsGetDSTimeStampStr(user.BadPwdTime), user.LogonCount, user.BadPwdCount, str_uac, str_anc,
               str(user.DialInAccessPermission), "", "", "", ""
               ])

    if pwdump == True:
        sys.stdout.write("\nPassword hashes:")
        (lm, nt) = user.getPasswordHashes()
        if nt != '':
            if pwdformat == 'john':
                sys.stdout.write("\n\t" + format_john(user.SAMAccountName,str(user.SID),nt,'NT'))
                ntof.writelines(format_john(user.SAMAccountName, str(user.SID), nt, 'NT') + "\n")
            if lm != '':
                if pwdformat == 'john':
                    sys.stdout.write("\n\t" + format_john(user.SAMAccountName,str(user.SID),lm,'LM'))
                    lmof.writelines(format_john(user.SAMAccountName, str(user.SID), lm, 'LM') + "\n")
                if pwdformat == 'ocl':
                    sys.stdout.write("\n\t" + format_ocl(user.SAMAccountName, lm))
                    lmof.writelines(format_ocl(user.SAMAccountName, lm) + "\n")
            if pwdformat == 'ophc':
                if lm != '':
                    sys.stdout.write("\n\t" + format_ophc(user.SAMAccountName,str(user.SID),lm,nt))
                    ntof.writelines(format_ophc(user.SAMAccountName, str(user.SID), lm, nt) + "\n")
                else:
                    sys.stdout.write("\n\t" + format_ophc(user.SAMAccountName,str(user.SID),"",nt))
                    ntof.writelines(format_ophc(user.SAMAccountName, str(user.SID), "", nt) + "\n")
            if pwdformat == 'ocl':
                sys.stdout.write("\n\t" + format_ocl(user.SAMAccountName, nt))
                ntof.writelines(format_ocl(user.SAMAccountName, nt) + "\n")
                
    
    if pwhdump == True:
        sys.stdout.write("\nPassword history:")
        lmhistory = None
        nthistory = None
        (lmhistory, nthistory) = user.getPasswordHistory()
        if nthistory != None:
            if pwdformat == 'john':
                hashid = 0
                for nthash in nthistory:
                    sys.stdout.write("\n\t" + format_john(user.SAMAccountName + "_nthistory" + str(hashid), str(user.SID), nthash, 'NT'))
                    ntof.writelines(format_john(user.SAMAccountName + "_nthistory" + str(hashid), str(user.SID), nthash, 'NT') + "\n")
                    hashid += 1
                if lmhistory != None:
                    hashid = 0
                    for lmhash in lmhistory:
                        sys.stdout.write("\n\t" + format_john(user.SAMAccountName + "_lmhistory" + str(hashid), str(user.SID), lmhash, 'LM'))
                        lmof.writelines(format_john(user.SAMAccountName + "_lmhistory" + str(hashid), str(user.SID), lmhash, 'LM') + "\n")
                        hashid += 1
            if pwdformat == 'ocl':
                hashid = 0
                for nthash in nthistory:
                    sys.stdout.write("\n\t" + format_ocl(user.SAMAccountName + "_nthistory" + str(hashid), nthash))
                    ntof.writelines(format_ocl(user.SAMAccountName + "_nthistory" + str(hashid), nthash) + "\n")
                    hashid += 1
                if lmhistory != None:
                    hashid = 0
                    for lmhash in lmhistory:
                        sys.stdout.write("\n\t" + format_ocl(user.SAMAccountName + "_lmhistory" + str(hashid), lmhash))
                        lmof.writelines(format_ocl(user.SAMAccountName + "_lmhistory" + str(hashid), lmhash) + "\n")
                        hashid += 1
            if pwdformat == 'ophc':
                if lmhistory != None:
                    for hashid in range(0,len(nthistory) - 1):
                        sys.stdout.write("\n\t" + format_ophc(user.SAMAccountName + "_history" + str(hashid), str(user.SID), lmhistory[hashid], nthistory[hashid]))
                        ntof.writelines(format_ophc(user.SAMAccountName + "_history" + str(hashid), str(user.SID), lmhistory[hashid], nthistory[hashid]) + "\n")                        

    
    if certdump == True and user.Certificate != "":
        sys.stdout.write("\nCertificate:\n")
        sys.stdout.write(dump(user.Certificate,16,16))
        
    if suppcreddump == True:
        creds = None
        creds = user.getSupplementalCredentials()
        if creds != None:
            sys.stdout.write("\nSupplemental credentials:\n")
            creds.Print("  ")
    
    if grpdump == True:
        sys.stdout.write("\nMember of:")
        if user.PrimaryGroupID != -1:
            for g in groups:
                if g.SID.RID == user.PrimaryGroupID:
                    if csvoutfile != "":
                        write_csv([user.RecordId, user.Name, user.PrincipalName, user.SAMAccountName,
                           user.getSAMAccountType(), str(user.GUID), str(user.SID),
                           dsGetDSTimeStampStr(user.WhenCreated), dsGetDSTimeStampStr(user.WhenChanged),
                           dsGetDSTimeStampStr(user.AccountExpires), dsGetDSTimeStampStr(user.PasswordLastSet),
                           dsGetDSTimeStampStr(user.LastLogon), dsGetDSTimeStampStr(user.LastLogonTimeStamp),
                           dsGetDSTimeStampStr(user.BadPwdTime), user.LogonCount, user.BadPwdCount, str_uac, str_anc,
                           str(user.DialInAccessPermission), g.Name, str(g.SID), "Y", ""
                           ])
                    sys.stdout.write("\n\t%s (%s) (P)" % (g.Name, str(g.SID)))
        grouplist = user.getMemberOf()
        for groupdata in grouplist:
            (groupid, deltime) = groupdata
            group = None
            try:
                group = dsGroup(db, groupid)
            except:
                sys.stderr.write("\n[!] Unable to instantiate group object (record id: %d)" % groupid)
                continue
            if deltime == -1:
                if csvoutfile != "":
                    write_csv([user.RecordId, user.Name, user.PrincipalName, user.SAMAccountName,
                           user.getSAMAccountType(), str(user.GUID), str(user.SID),
                           dsGetDSTimeStampStr(user.WhenCreated), dsGetDSTimeStampStr(user.WhenChanged),
                           dsGetDSTimeStampStr(user.AccountExpires), dsGetDSTimeStampStr(user.PasswordLastSet),
                           dsGetDSTimeStampStr(user.LastLogon), dsGetDSTimeStampStr(user.LastLogonTimeStamp),
                           dsGetDSTimeStampStr(user.BadPwdTime), user.LogonCount, user.BadPwdCount, str_uac, str_anc,
                           str(user.DialInAccessPermission), group.Name, str(group.SID), "N", ""
                           ])
                sys.stdout.write("\n\t%s (%s)" % (group.Name, group.SID))
            else:
                if csvoutfile != "":
                    write_csv([user.RecordId, user.Name, user.PrincipalName, user.SAMAccountName,
                           user.getSAMAccountType(), str(user.GUID), str(user.SID),
                           dsGetDSTimeStampStr(user.WhenCreated), dsGetDSTimeStampStr(user.WhenChanged),
                           dsGetDSTimeStampStr(user.AccountExpires), dsGetDSTimeStampStr(user.PasswordLastSet),
                           dsGetDSTimeStampStr(user.LastLogon), dsGetDSTimeStampStr(user.LastLogonTimeStamp),
                           dsGetDSTimeStampStr(user.BadPwdTime), user.LogonCount, user.BadPwdCount, str_uac, str_anc,
                           str(user.DialInAccessPermission), group.Name, str(group.SID), "Y", dsGetDSTimeStampStr(dsConvertToDSTimeStamp(deltime))
                           ])
                sys.stdout.write("\n\t%s (%s) - Deleted: %s" % (group.Name, group.SID, 
                            dsGetDSTimeStampStr(dsConvertToDSTimeStamp(deltime))))

    sys.stdout.write("\n")
    sys.stdout.flush()

if len(sys.argv) < 4:
    usage()
    sys.exit(1)

#rid = -1
#name = ""
sid  = ""
guid = ""
syshive = ""
ntoutfile = ""
lmoutfile = ""
pwdformat = ""
csvoutfile = ""
pwdump = False
pwhdump = False
certdump = False
suppcreddump = False
grpdump = False
optid = 0
ntof = None
lmof = None
csvof = None
reName = None
only_active = False
only_locked = False
uac_flags = None


sys.stderr.write("\n[+] Started at: %s" % time.strftime(
                                        "%a, %d %b %Y %H:%M:%S UTC",
                                        time.gmtime()))
sys.stderr.write("\n[+] Started with options:")
for opt in sys.argv:
#     if opt == "--rid":
#         if len(sys.argv) < optid + 2:
#             usage()
#             sys.exit(1)
#         rid = int(sys.argv[optid + 1])
#         sys.stderr.write("\n\t[-] User RID: %d" % rid)
    if opt == "--name":
        if len(sys.argv) < optid + 2:
            usage()
            sys.exit(1)
        name = sys.argv[optid + 1]
        reName = re.compile(name)
        sys.stderr.write("\n\t[-] User name: %s" % name)
    if opt == "--active":
        if uac_flags != None:
            sys.stderr.write("\n[!] Error! This option cannot be used with --uac!")
            sys.exit(1)
        only_active = True
        sys.stderr.write("\n\t[-] Extracting only active accounts")
    if opt == "--locked":
        if uac_flags != None:
            sys.stderr.write("\n[!] Error! This option cannot be used with --uac!")
            sys.exit(1)
        only_locked = True
        sys.stderr.write("\n\t[-] Extracting only locked accounts")
    if opt == "--uac":
        if len(sys.argv) < optid + 2:
            usage()
            sys.exit(1)
        uac_flags = int(sys.argv[optid + 1], 16)
        sys.stderr.write("\n\t[-] Extracting only accounts with UAC flags: " + sys.argv[optid + 1])
    if opt == "--sid":
        if len(sys.argv) < optid + 2:
            usage()
            sys.exit(1)
        sid = sys.argv[optid + 1]
        sys.stderr.write("\n\t[-] User SID: %s" % sid)
    if opt == "--guid":
        if len(sys.argv) < optid + 2:
            usage()
            sys.exit(1)
        guid = sys.argv[optid + 1]
        sys.stderr.write("\n\t[-] User GUID: %s" % guid)
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
    if opt == "--certificates":
        certdump = True
        sys.stderr.write("\n\t[-] Extracting certificates")
    if opt == "--supplcreds":
        suppcreddump = True
        sys.stderr.write("\n\t[-] Extracting supplemental credentials")
    if opt == "--membership":
        grpdump = True
        sys.stderr.write("\n\t[-] Extracting memberships")
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

if (pwdump or pwhdump) and syshive == "":
    sys.stderr.write("\n[!] Error! syshive not specified!\n")
    usage()
    sys.exit(1)
    
if suppcreddump == True and syshive == "":
    sys.stderr.write("\n[!] Error! syshive not specified!\n")
    usage()
    sys.exit(1)

# Setting up the environment
if not checkfile(sys.argv[1]):
    sys.stderr.write("\n[!] Error! datatable cannot be found!\n")
    sys.exit(1)
if not checkfile(sys.argv[2]):
    sys.stderr.write("\n[!] Error! linktable cannot be found!\n")
    sys.exit(1)
wd = ensure_dir(sys.argv[3])

if pwdump == True or pwhdump == True:
    if pwdformat == "":
        sys.stderr.write("\n[!] Error! Missing password hash output format!\n")
        sys.stderr.flush()
        sys.exit(1)
    if ntoutfile == "":
        sys.stderr.write("\n[!] Error! Missing password hash output file!\n")
        sys.stderr.flush()
        sys.exit(1)
    if (pwdformat == "john" or pwdformat == "ocl") and lmoutfile == "":
        sys.stderr.write("\n[!] Error! Missing LM hash output file!\n")
        sys.stderr.flush()
        sys.exit(1)

if csvoutfile != "":
    init_csv(path.join(wd, csvoutfile))

if pwdump == True or pwhdump == True:
    ntof = open(path.join(wd, ntoutfile), 'a')
    if pwdformat == 'john' or pwdformat == 'ocl':
        lmof = open(path.join(wd, lmoutfile), 'a')

# Initializing engine
db = dsInitDatabase(sys.argv[1], wd)
dl = dsInitLinks(sys.argv[2], wd)
    
if pwdump or pwhdump or suppcreddump:
    dsInitEncryption(syshive)

utype = -1
utype = dsGetTypeIdByTypeName(db, "Person")
if utype == -1:
    sys.stderr.write("\n[!] Unable to get type id for Person")
    sys.exit(1)

gtype = -1
gtype = dsGetTypeIdByTypeName(db, "Group")
if gtype == -1:
    sys.stderr.write("\n[!] Unable to get type id for Group")
    sys.exit(1)

groups = []
if grpdump == True:
    sys.stderr.write("\n[+] Extracting group objects...")
    for recordid in dsMapLineIdByRecordId:
        if int(dsGetRecordType(db, recordid)) == gtype:
            groups.append(dsGroup(db, recordid))

if csvoutfile != "":
    write_csv(["Record ID", "User name", "User principal name", "SAM account name",
            "SAM account type", "GUID", "SID", 
            "When created", "When changed",
            "Account expires", "Password last set",
            "Last logon", "Last logon timestamp",
            "Bad password time", "Logon count", "Bad password count", "User Account Control",
            "Ancestors", "Dial-In Permission", "Member of", "Group SID", "Primary group", "Membership deletion time"
            ])

sys.stdout.write("\nList of users:")
sys.stdout.write("\n==============")

if sid != "":
    recordid = int(dsMapRecordIdBySID[sid])
    if int(dsGetRecordType(db, recordid)) == utype:
        user = None
        try:
            user = dsUser(db, recordid)
        except KeyboardInterrupt:
            raise KeyboardInterrupt
        except:
            sys.stderr.write("\n[!] Unable to instantiate user object (record id: %d)" % recordid)
            sys.exit(1)
        
        if only_active == True:
            if user.isActive == True:
                processUser(user)
        elif only_locked == True:
            if user.isLocked == True or user.isDisabled == True:
                processUser(user)
        else:
            processUser(user)
elif guid !="":
    recordid = int(dsMapRecordIdByGUID[guid])
    if int(dsGetRecordType(db, recordid)) == utype:
        user = None
        try:
            user = dsUser(db, recordid)
        except KeyboardInterrupt:
            raise KeyboardInterrupt
        except:
            sys.stderr.write("\n[!] Unable to instantiate user object (record id: %d)" % recordid)
            sys.exit(1)
        
        if only_active == True:
            if user.isActive == True:
                processUser(user)
        elif only_locked == True:
            if user.isLocked == True or user.isDisabled == True:
                processUser(user)
        else:
            processUser(user)
else:
    for recordid in dsMapRecordIdByTypeId[utype]:
        user = None
        try:
            user = dsUser(db, recordid)
        except KeyboardInterrupt:
            raise KeyboardInterrupt
        except:
            sys.stderr.write("\n[!] Unable to instantiate user object (record id: %d)" % recordid)
            continue
            
        if reName != None and \
           not reName.search(user.Name) and \
           not reName.search(user.SAMAccountName) and \
           not reName.search(user.PrincipalName):
            user = None
            continue
        
        if only_active == True:
            if user.isActive == True:
                processUser(user)
        elif only_locked == True:
            if user.isLocked == True or user.isDisabled == True:
                processUser(user)
        elif uac_flags != None:
            if user.UserAccountControl & uac_flags == uac_flags:
                processUser(user)
        else:
            processUser(user)

if csvoutfile != "":
    close_csv()

if ntof != None:
    ntof.close()
if lmof != None:
    lmof.close()
