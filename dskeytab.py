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
@author:        Sergey Kubasov
@license:       GNU General Public License 2.0 or later
@contact:       kubasov.s@gmail.com
'''
import sys, struct
from ntds.version import *
from ntds.dsdatabase import *
from ntds.dslink import *
from ntds.dsobjects import *
from framework.addrspace import HiveFileAddressSpace
from framework.win32.hashdump import find_control_set
from framework.win32.rawreg import get_root, open_key
from ntds.lib.fs import *

def usage():
    sys.stderr.write("\nDSKeytab v" + str(ntds.version.version))
    sys.stderr.write("\nGenerate keytab file")
    sys.stderr.write("\n\nusage: {0} <datatable> <linktable> <system hive> <work directory> <keytab>".format(sys.argv[0]))
    sys.stderr.write("\n\n  options:")
    sys.stderr.write("\n    --debug")
    sys.stderr.write("\n          Turn on detailed error messages and stack trace")
    sys.stderr.write("\n")

if len(sys.argv) < 6:
    usage()
    sys.exit(1)

# Setting up the environment
if not checkfile(sys.argv[1]):
    sys.stderr.write("\n[!] Error! datatable cannot be found!\n")
    sys.exit(1)
if not checkfile(sys.argv[2]):
    sys.stderr.write("\n[!] Error! linktable cannot be found!\n")
    sys.exit(1)
wd = ensure_dir(sys.argv[4])

# Initializing engine
db = dsInitDatabase(sys.argv[1], wd)
dl = dsInitLinks(sys.argv[2], wd)
systemHive = sys.argv[3]
dsInitEncryption(systemHive)
keytabFilePath = sys.argv[5]

def dsReadNtdsMachineDNName():
    """
    Every keytab entry must include a realm that may be extracted from user
    principal name attribute of the corresponding pricipal object. However
    some security principals have blank user principal names, so we need go get
    the realm the other way.
    
    You may notice that user principal name is missing on computer accounts and 
    on user accounts that was created on the server before it was promoted to Domain Controller.
    For example, Guest and Administrator accounts do not have user principal names.
    Default realm is uppercased domain name.
    
    Domain name is stored in ATTm1376281 attribute of Dns-Zone object 
    (dsGetTypeIdByTypeName(db, "Dns-Zone")). Unfortunately there are a number
    of Dns-Zone objects and it's unclear how to select the right one.
    Dns-Zone records probably originate from DNS service hosted on the same machine.
    Active Directory Domain Services Installation Wizard insists on installing DNS,
    but it is not imposible to bump into a Domain Controller missing DNS.
    
    The idea implemented here relies on reading parameters of NTDS service,
    namely "Machine DN Name" value. It is the distinguished name of the current
    machine. For example:
    CN=NTDS Settings,CN=WIN2008X64R2S7,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=universe3,DC=test
    Components at the end of the value prefixed with "DC=" string are parts of domain.
    
    You are welcome to propose a better way of detecting the current domain.
    """

    sysaddr = HiveFileAddressSpace(systemHive)
    cs = find_control_set(sysaddr)
    ntdsParams = ["ControlSet%03d" % cs, "services", "NTDS", "Parameters"]
    root = get_root(sysaddr)
    if not root:
        return None
    key = open_key(root, ntdsParams)
    if not key:
        return None
    for v in key.ValueList.List:
        if v.Name.lower() == "Machine DN Name".lower():
            if v.Type.value != 1:
                return None
            if v.DataLength.value & (1 << 31) != 0:
                # not implemented
                return None
            data = v.space.read(v.Data.value, v.DataLength.value)
            return data.decode('utf-16').strip(u'\x00')
    return None
    
def dsGetMachineDomain():
    dn = dsReadNtdsMachineDNName()
    if dn == None:
        return None
    ind = dn.lower().find(",dc=")
    if ind < 0:
        return None
    domainDN = dn[ind+1:]
    parts = domainDN.split(',')
    for i in range(len(parts)):
        if not parts[i].lower().startswith("dc="):
            return None
        parts[i] = parts[i][3:]
    return ".".join(parts).encode('ascii')

def dsAddPrincipalEntries(principal, keytabFile):
    '''
    Add keytab entries for the specified principal to keytab file.
    '''
    upn = principal.PrincipalName
    if upn == "":
        realm = defaultRealm
    else:
        name1, realm = upn.split('@')
        if realm == "":
            realm = defaultRealm
    SAMAccountName = principal.SAMAccountName
    if SAMAccountName == "":
        sys.stderr.write("SAM account name is blank. Skipping principal.\n")
        return
    if realm == "":
        sys.stderr.write("Realm is blank. Skipping principal {0}.\n".format(SAMAccountName))
        return
    sys.stderr.write("Processing principal {0}.\n".format(SAMAccountName))
    timestamp = dsGetPOSIXTimeStamp(principal.PasswordLastSet)
    nameType = 1 # KRB5_NT_PRINCIPAL
    kerberosKeys = dsGetPrincipalKerberosKeys(principal)
    if kerberosKeys != None:
        sys.stderr.write("Using supplemental credentials.\n")
        dsPrincipalKeytabFromSupplementalCredentials(kerberosKeys, realm, SAMAccountName, nameType, timestamp)
        return
    (lmhistory, nthistory) = principal.getPasswordHistory()
    if nthistory != None and len(nthistory) > 0:
        sys.stderr.write("Using NT history.\n")
        dsPrincipalKeytabFromNTHistory(nthistory, realm, SAMAccountName, nameType, timestamp)
        return
    (lm, nt) = principal.getPasswordHashes()
    if nt != "":
        sys.stderr.write("Using NT hash.\n")
        dsPrincipalKeytabFromNTHash(nt, realm, SAMAccountName, nameType, timestamp)
        return
    sys.stderr.write("No information about kerberos keys.\n")

def dsGetPrincipalKerberosKeys(principal):
    creds = principal.getSupplementalCredentials()
    if creds == None:
        return None
    kerberosKeys = creds.KerberosNewerKeys
    if kerberosKeys == None:
        kerberosKeys = creds.KerberosKeys
    return kerberosKeys

def dsPrincipalKeytabFromSupplementalCredentials(kerberosKeys, realm, SAMAccountName, nameType, timestamp):
    '''
    Key version number are hard coded and definitely incorrect.
    As luck would have it Wireshark does not care about kvn and decrypt the traffic
    anyway.
    
    How to determine the key version number of a key?
    Supplemental credentials structure does not include kvn. This structure is
    documented in msdn, all fields are known. If we update password of user three times
    in succession (to fill all three fields Credentials, OldCredentials,
    OlderCredentials) each time using the same password, following password updates
    does not change the structure. The structure remains the same (binary identical).
    For experiments I've used the following command
    ktpass /princ host/user1.universe.test@UNIVERSE.TEST /mapuser user1 /out \temp\user1.keytab /crypto all /ptype KRB5_NT_PRINCIPAL /pass 1
    Each run of this command update the password, outputs new key version number.
    Wireshark capture confirms that kvn really changes.
    It's logical to expect that kvn is stored in attributes of the corresponding
    user object.
    In practise we see that the following attributes changes after password update:
    dsSupplementalCredentialsIndex, dsPasswordLastSetIndex, dsUSNChangedIndex,
    dsWhenChangedIndex, dsNTHashIndex. While the value of dsSupplementalCredentialsIndex
    and dsNTHashIndex attributes, changes the decrypted value of these attributes
    remains the same. These attributes change while a new initialization vector
    is used to encrypt the value. It seams that new IV is a random number, but
    maybe it includes kvn?
    '''
    for key in kerberosKeys.Credentials:
        keytabFile.write(dsPackKeytabEntry(realm, SAMAccountName, nameType, timestamp, 3, key.KeyType, key.Key))
    for key in kerberosKeys.OldCredentials:
        keytabFile.write(dsPackKeytabEntry(realm, SAMAccountName, nameType, 0, 2, key.KeyType, key.Key))
    for key in kerberosKeys.OlderCredentials:
        keytabFile.write(dsPackKeytabEntry(realm, SAMAccountName, nameType, 0, 1, key.KeyType, key.Key))

def dsPrincipalKeytabFromNTHash(nt, realm, SAMAccountName, nameType, timestamp):
    keytabFile.write(dsPackKeytabEntry(realm, SAMAccountName, nameType, timestamp, 1, 23, nt))

def dsPrincipalKeytabFromNTHistory(nthistory, realm, SAMAccountName, nameType, timestamp):
    kvn = len(nthistory)
    for nt in nthistory:
        keytabFile.write(dsPackKeytabEntry(realm, SAMAccountName, nameType, timestamp, kvn, 23, nt))
        kvn -= 1
        timestamp = 0

def dsPackKeytabEntry(realm, SAMAccountName, nameType, timestamp, keyVersionNumber, keyType, key):
    '''
    Generate a keytab entry
    '''
    # type -140 corresponds to KERB_ETYPE_RC4_PLAIN content in NTSecAPI.h header
    # In Wireshark output we see 23 encryption type, that is rc4-hmac according to RFC 3961.
    # Wireshark successfully decrypts traffic when the type is 23, and does not
    # decrypt when type is -140.
    if keyType == -140:
        keyType = 23
    s = struct.pack(">HH", 1, len(realm))
    s += realm
    s += struct.pack(">H", len(SAMAccountName))
    s += SAMAccountName
    s += struct.pack(">IIBHH", nameType, timestamp, keyVersionNumber & 0xff,
        keyType & 0xffff, len(key))
    s += key
    s += struct.pack(">I", keyVersionNumber)
    return struct.pack(">i", len(s)) + s

utype = -1
utype = dsGetTypeIdByTypeName(db, "Person")
if utype == -1:
    sys.stderr.write("Unable to get type id for Person\n")
    sys.exit(1)

ctype = -1
ctype = dsGetTypeIdByTypeName(db, "Computer")
if ctype == -1:
    sys.stderr.write("Unable to get type id for Computer\n")
    sys.exit(1)

defaultRealm = dsGetMachineDomain()
if defaultRealm == None:
    sys.stderr.write("Default realm is not detected\n")
    exit(0)
#print "default realm:", defaultRealm, type(defaultRealm)

with open(keytabFilePath, 'wb') as keytabFile:
    keytabFile.write("\x05\x02")
    for recordid in dsMapLineIdByRecordId:
        recordtype = int(dsGetRecordType(db, recordid))
        if recordtype == utype:
            principal = dsUser(db, recordid)
        elif recordtype == ctype:
            principal = dsComputer(db, recordid)
        else:
            continue
            
        dsAddPrincipalEntries(principal, keytabFile)

