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

from ntds.version import *
from ntds.dsdatabase import *
from ntds.dsrecord import *
from ntds.dsobjects import *
from ntds.dslink import *
from ntds.dstime import *
from ntds.lib.fs import *
from ntds.lib.csvoutput import *


def usage():
    sys.stderr.write("\nDSGroups v" + str(ntds.version.version))
    sys.stderr.write("\nExtracts information related to group objects\n")
    sys.stderr.write("\nusage: %s <datatable> <linktable> <work directory> [option]" % sys.argv[0])
    sys.stderr.write("\n\n  datatable")
    sys.stderr.write("\n    The path to the file called datatable extracted by esedbexport")
    sys.stderr.write("\n  linktable")
    sys.stderr.write("\n    The path to the file called linktable extracted by esedbexport")
    sys.stderr.write("\n  work directory")
    sys.stderr.write("\n    The path to the directory where ntdsxtract should store its")
    sys.stderr.write("\n    cache files and output files. If the directory does not exist")
    sys.stderr.write("\n    it will be created.")
    sys.stderr.write("\n\n  options:")
    sys.stderr.write("\n    --rid <group rid>")
    sys.stderr.write("\n          Extracts only the group identified by <group id>")
    sys.stderr.write("\n    --name <group name regexp>")
    sys.stderr.write("\n          Extracts only the group identified by the refular expression")
    sys.stderr.write("\n    --members")
    sys.stderr.write("\n          Extracts the members of the group")
    sys.stderr.write("\n    --csvoutfile <name of the CSV output file>")
    sys.stderr.write("\n          The filename of the csv file to which ntdsxtract should write the")
    sys.stderr.write("\n          output")
    sys.stderr.write("\n    --debug")
    sys.stderr.write("\n          Turn on detailed error messages and stack trace")
    sys.stderr.write("\n")
    sys.stderr.flush()
    
if len(sys.argv) < 4:
    usage()
    sys.exit(1)

sys.stderr.write("\n[+] Started at: %s" % time.strftime(
                                        "%a, %d %b %Y %H:%M:%S UTC",
                                        time.gmtime()))
sys.stderr.write("\n[+] Started with options:")
optid = 0
rid = ""
name = ""
grpdump = False
csvoutfile = ""
csvof = None
reName = None

for opt in sys.argv:
    if opt == "--rid":
        if len(sys.argv) < 5:
            usage()
            sys.exit(1)
        rid = int(sys.argv[optid + 1])
        sys.stderr.write("\n\t[-] Group RID: %d" % rid)
    if opt == "--name":
        if len(sys.argv) < 5:
            usage()
            sys.exit(1)
        name = sys.argv[optid + 1]
        reName = re.compile(name)
        sys.stderr.write("\n\t[-] Group name: %s" % name)
    if opt == "--members":
        grpdump = True
        sys.stderr.write("\n\t[-] Extracting group members")
    if opt == "--csvoutfile":
        if len(sys.argv) < optid + 2:
            usage()
            sys.exit(1)
        csvoutfile = sys.argv[optid + 1]
        sys.stderr.write("\n\t[-] CSV output filename: " + sys.argv[optid + 1])
    optid += 1
sys.stderr.write("\n")
sys.stderr.flush()

# Setting up the environment
if not checkfile(sys.argv[1]):
    sys.stderr.write("\n[!] Error! datatable cannot be found!\n")
    sys.exit(1)
if not checkfile(sys.argv[2]):
    sys.stderr.write("\n[!] Error! linktable cannot be found!\n")
    sys.exit(1)
wd = ensure_dir(sys.argv[3])

if csvoutfile != "":
    init_csv(path.join(wd, csvoutfile))

# Initializing engine
db = dsInitDatabase(sys.argv[1], wd)
dl = dsInitLinks(sys.argv[2], wd)

gtype = dsGetTypeIdByTypeName(db, "Group")
utype = dsGetTypeIdByTypeName(db, "Person")
ctype = dsGetTypeIdByTypeName(db, "Computer")

users = []
if grpdump == True:
    sys.stderr.write("\n[+] Extracting user objects...")
    for recordid in dsMapLineIdByRecordId:
        if (int(dsGetRecordType(db, recordid)) == utype or
            int(dsGetRecordType(db, recordid)) == ctype):
            try:
                user = dsUser(db, recordid)
            except:
                sys.stderr.write("\n[!] Unable to instantiate user object (record id: %d)" % recordid)
                continue
            users.append(user)
            user = None
        
if csvoutfile != "":
    write_csv(["Record ID", "Group name", "GUID", "SID", "When created",
               "When changed", "Member object", "Member object GUID",
               "Member object type", "Primary group of member",
               "Membership deletion time"
            ])
        
sys.stdout.write("\n\nList of groups:")
sys.stdout.write("\n===============")
for recordid in dsMapLineIdByRecordId:
    if int(dsGetRecordType(db, recordid)) == gtype:
        try:
            group = dsGroup(db, recordid)
        except:
            sys.stderr.write("\n[!] Unable to instantiate group object (record id: %d)" % recordid)
            continue
        if rid != "" and group.SID.RID != int(rid):
            group = None
            continue
        if reName != None and not reName.search(group.Name):
            group = None
            continue
        
        sys.stdout.write("\nRecord ID:    %d" % group.RecordId)
        sys.stdout.write("\nGroup Name:   %s" % group.Name)
        sys.stdout.write("\nGUID:         %s" % str(group.GUID))
        sys.stdout.write("\nSID:          %s" % str(group.SID))
        sys.stdout.write("\nWhen created: %s" % dsGetDSTimeStampStr(group.WhenCreated))
        sys.stdout.write("\nWhen changed: %s" % dsGetDSTimeStampStr(group.WhenChanged))
        
        # The main group record
        if csvoutfile != "":
            write_csv([group.RecordId, group.Name, str(group.GUID),
                str(group.SID), "'" + dsGetDSTimeStampStr(group.WhenCreated),
                "'" + dsGetDSTimeStampStr(group.WhenChanged),
                "", "", "" ])
        
        if grpdump == True:
            sys.stdout.write("\nMembers:")
            for u in users:
                if u.PrimaryGroupID != -1:
                    if u.PrimaryGroupID == group.SID.RID:
                        if csvoutfile != "":
                            write_csv([group.RecordId, group.Name, str(group.GUID),
                                    str(group.SID), "=\"" + dsGetDSTimeStampStr(group.WhenCreated) + "\"",
                                    "=\"" + dsGetDSTimeStampStr(group.WhenChanged) + "\"",
                                    u.Name, str(u.GUID), u.Type, "Y", ""
                                    ])
                        sys.stdout.write("\n\t%s (%s) (%s) (P)" % (u.Name, str(u.GUID), u.Type))
            memberlist = group.getMembers()
            for memberdata in memberlist:
                (memberid, deltime) = memberdata
                try:
                    member = dsObject(db, memberid)
                except:
                    continue
                if member == None:
                    continue
                if deltime == -1:
                    if csvoutfile != "":
                        write_csv([group.RecordId, group.Name, str(group.GUID),
                            str(group.SID), "=\"" + dsGetDSTimeStampStr(group.WhenCreated) + "\"",
                            "=\"" + dsGetDSTimeStampStr(group.WhenChanged) + "\"",
                            member.Name, str(member.GUID), member.Type, "N", ""
                            ])
                    sys.stdout.write("\n\t%s (%s) (%s)" % (member.Name, str(member.GUID), member.Type))
                else:
                    if csvoutfile != "":
                        write_csv([group.RecordId, group.Name, str(group.GUID),
                            str(group.SID), "=\"" + dsGetDSTimeStampStr(group.WhenCreated) + "\"",
                            "=\"" + dsGetDSTimeStampStr(group.WhenChanged) + "\"",
                            member.Name, str(member.GUID), member.Type, "N", "=\"" + dsGetDSTimeStampStr(dsConvertToDSTimeStamp(deltime)) + "\""
                            ])
                    sys.stdout.write("\n\t%s (%s) (%s) - Deleted: %s" % (member.Name, 
                                                                         str(member.GUID), 
                                                                         member.Type, 
                                                                         dsGetDSTimeStampStr(dsConvertToDSTimeStamp(deltime))))
                member = None
        
        group = None
        sys.stdout.write("\n")

if csvoutfile != "":
    close_csv()

sys.stdout.flush()
