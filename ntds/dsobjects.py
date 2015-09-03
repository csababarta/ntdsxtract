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
import ntds.dsfielddictionary
from ntds.dsdatabase import *
from ntds.dslink import *
from ntds.dsrecord import *
from ntds.dstime import *
from ntds.dsencryption import *

from ntds.lib.guid import *
from ntds.lib.sid import *
from ntds.lib.dump import *

class dsObject:
    '''
    The main AD class
    '''
    DB          = None
    Record      = None
    Name        = ""
    RecordId    = -1
    TypeId      = -1
    Type        = ""
    GUID        = None
    WhenCreated = -1
    WhenChanged = -1
    USNCreated  = -1
    USNChanged  = -1
    IsDeleted   = False
    
    def __init__(self, dsDatabase, dsRecordId):
        '''
        Constructor
        '''
        self.DB = dsDatabase
        self.RecordId = dsRecordId
        self.Record = dsGetRecordByRecordId(dsDatabase, self.RecordId)
        if self.Record != None:
            self.Name   = self.Record[ntds.dsfielddictionary.dsObjectName2Index]
            self.TypeId = dsGetRecordType(dsDatabase, self.RecordId)
            self.Type   = dsGetTypeName(dsDatabase, self.TypeId)

            if self.Record[ntds.dsfielddictionary.dsObjectGUIDIndex] != "":
                self.GUID = GUID(self.Record[ntds.dsfielddictionary.dsObjectGUIDIndex])
        
            if self.Record[ntds.dsfielddictionary.dsWhenCreatedIndex] != "":
                self.WhenCreated = dsConvertToDSTimeStamp(
                                self.Record[ntds.dsfielddictionary.dsWhenCreatedIndex]
                                                      )
            else:
                self.WhenCreated = dsConvertToDSTimeStamp(
                                self.Record[ntds.dsfielddictionary.dsRecordTimeIndex]
                                                      )
        
            if self.Record[ntds.dsfielddictionary.dsWhenChangedIndex] != "":
                self.WhenChanged = dsConvertToDSTimeStamp(
                                self.Record[ntds.dsfielddictionary.dsWhenChangedIndex]
                                                      )

            if self.Record[ntds.dsfielddictionary.dsUSNCreatedIndex] != "":
                self.USNCreated = int(self.Record[ntds.dsfielddictionary.dsUSNCreatedIndex])
        
            if self.Record[ntds.dsfielddictionary.dsUSNChangedIndex] != "":
                self.USNChanged = int(self.Record[ntds.dsfielddictionary.dsUSNChangedIndex])
            
            if self.Record[ntds.dsfielddictionary.dsIsDeletedIndex] != "":
                self.IsDeleted = True
            
    def getChilds(self):
        '''
        Returns the child objects
        '''
        try:
            childlist = dsMapChildsByRecordId[self.RecordId]
            return childlist
        except:
            return []

    def getAncestors(self, dsDatabase):
        '''
        Returns the ancestors
        '''
        ancestorlist = []
        ancestorvalue = self.Record[ntds.dsfielddictionary.dsAncestorsIndex] 
        if ancestorvalue != "":
            l = len(ancestorvalue) / 8
            for aid in range(0, l):
                (ancestorid,) = unpack('I', unhexlify(ancestorvalue[aid * 8:aid * 8 + 8]))
                ancestor = dsObject(dsDatabase, ancestorid)
                if ancestor == None:
                    continue
                ancestorlist.append(ancestor)
        return ancestorlist
            
class dsFVERecoveryInformation(dsObject):
    '''
    The class used for representing BitLocker recovery information stored in AD
    '''
    RecoveryGUID = None
    VolumeGUID = None
    RecoveryPassword = ""
    FVEKeyPackage = ""
    
    def __init__(self, dsDatabase, dsRecordId):
        '''
        Constructor
        '''
        dsObject.__init__(self, dsDatabase, dsRecordId)
        if self.Record[ntds.dsfielddictionary.dsRecoveryGUIDIndex] != "":
            self.RecoveryGUID = GUID(self.Record[ntds.dsfielddictionary.dsRecoveryGUIDIndex])
        if self.Record[ntds.dsfielddictionary.dsVolumeGUIDIndex] != "":
            self.VolumeGUID = GUID(self.Record[ntds.dsfielddictionary.dsVolumeGUIDIndex])
        self.RecoveryPassword = self.Record[ntds.dsfielddictionary.dsRecoveryPasswordIndex]
        self.FVEKeyPackage = self.Record[ntds.dsfielddictionary.dsFVEKeyPackageIndex]
        
        
                
class dsAccount(dsObject):
    '''
    The main account class
    '''
    SID                = None
    SAMAccountName     = ""
    PrincipalName  = ""
    SAMAccountType     = -1
    UserAccountControl = -1
    LogonCount         = -1
    LastLogon          = -1
    LastLogonTimeStamp = -1
    PasswordLastSet    = -1
    AccountExpires     = -1
    BadPwdTime         = -1
    SupplementalCredentials = ""
    PrimaryGroupID     = -1
    BadPwdCount        = -1
    DialInAccessPermission   = -1
    
    isLocked = False
    isDisabled = False
    isActive = False
    
    def __init__(self, dsDatabase, dsRecordId):
        '''
        Constructor
        '''
        dsObject.__init__(self, dsDatabase, dsRecordId)
        
        self.SID = SID(self.Record[ntds.dsfielddictionary.dsSIDIndex])
        self.SAMAccountName = self.Record[ntds.dsfielddictionary.dsSAMAccountNameIndex]
        self.PrincipalName = self.Record[ntds.dsfielddictionary.dsUserPrincipalNameIndex]
        if self.Record[ntds.dsfielddictionary.dsSAMAccountTypeIndex] != "":
            self.SAMAccountType = int(self.Record[ntds.dsfielddictionary.dsSAMAccountTypeIndex])
        
        if self.Record[ntds.dsfielddictionary.dsUserAccountControlIndex] != "":
            self.UserAccountControl = int(self.Record[ntds.dsfielddictionary.dsUserAccountControlIndex])
        
        if self.UserAccountControl != -1:
            if self.UserAccountControl & int("0x10", 16) == int("0x10", 16):
                self.isLocked = True
            if self.UserAccountControl & int("0x2", 16) == int("0x2", 16):
                self.isDisabled = True
            if not self.isLocked and not self.isDisabled:
                self.isActive = True
        
        if self.Record[ntds.dsfielddictionary.dsPrimaryGroupIdIndex] != "":
            self.PrimaryGroupID = int(self.Record[ntds.dsfielddictionary.dsPrimaryGroupIdIndex])
        if self.Record[ntds.dsfielddictionary.dsLogonCountIndex] != "":
            self.LogonCount = int(self.Record[ntds.dsfielddictionary.dsLogonCountIndex])
        else:
            self.BadPwdCount = -1
        if self.Record[ntds.dsfielddictionary.dsBadPwdCountIndex] != "":
            self.BadPwdCount = int(self.Record[ntds.dsfielddictionary.dsBadPwdCountIndex])
        else:
            self.BadPwdCount = -1
                        
        self.LastLogon = dsVerifyDSTimeStamp(self.Record[ntds.dsfielddictionary.dsLastLogonIndex])
        
        self.LastLogonTimeStamp = dsVerifyDSTimeStamp(self.Record[ntds.dsfielddictionary.dsLastLogonTimeStampIndex])
        
        self.PasswordLastSet = dsVerifyDSTimeStamp(self.Record[ntds.dsfielddictionary.dsPasswordLastSetIndex])
        
        self.AccountExpires = dsVerifyDSTimeStamp(self.Record[ntds.dsfielddictionary.dsAccountExpiresIndex])
        
        self.BadPwdTime = dsVerifyDSTimeStamp(self.Record[ntds.dsfielddictionary.dsBadPwdTimeIndex])
        
        if self.Record[ntds.dsfielddictionary.dsDialInAccessPermission] != "":
            self.DialInAccessPermission = int(self.Record[ntds.dsfielddictionary.dsDialInAccessPermission])
        else:
            self.DialInAccessPermission = -1
    
    def getPasswordHashes(self):
        lmhash = ""
        nthash = ""
        enclmhash = unhexlify(self.Record[ntds.dsfielddictionary.dsLMHashIndex][16:])
        encnthash = unhexlify(self.Record[ntds.dsfielddictionary.dsNTHashIndex][16:])
        if enclmhash != '':
            lmhash = dsDecryptWithPEK(ntds.dsfielddictionary.dsPEK, enclmhash)
            lmhash = hexlify(dsDecryptSingleHash(self.SID.RID, lmhash))
            if lmhash == '':
                lmhash = "NO PASSWORD"
        if encnthash != '':
            nthash = dsDecryptWithPEK(ntds.dsfielddictionary.dsPEK, encnthash)
            nthash = hexlify(dsDecryptSingleHash(self.SID.RID, nthash))
            if nthash == '':
                nthash = "NO PASSWORD"
        return (lmhash, nthash)
    
    def getPasswordHistory(self):
        lmhistory = []
        nthistory = []
        enclmhistory = unhexlify(self.Record[ntds.dsfielddictionary.dsLMHashHistoryIndex][16:])
        encnthistory = unhexlify(self.Record[ntds.dsfielddictionary.dsNTHashHistoryIndex][16:])
        slmhistory = dsDecryptWithPEK(ntds.dsfielddictionary.dsPEK, enclmhistory)
        snthistory = dsDecryptWithPEK(ntds.dsfielddictionary.dsPEK, encnthistory)
        if slmhistory != "":
            for hindex in range(0,len(slmhistory)/16):
                lmhash   = dsDecryptSingleHash(self.SID.RID, slmhistory[hindex*16:(hindex+1)*16])
                if lmhash == '':
                    lmhistory.append('NO PASSWORD')
                else:
                    lmhistory.append(hexlify(lmhash))
        if snthistory != "":
            for hindex in range(0,len(snthistory)/16):
                nthash = dsDecryptSingleHash(self.SID.RID, snthistory[hindex*16:(hindex+1)*16])
                if nthash == '':
                    nthistory.append('NO PASSWORD')
                else:
                    nthistory.append(hexlify(nthash))
        return (lmhistory, nthistory)
    
    def getSupplementalCredentials(self):
        self.SupplementalCredentials = self.Record[ntds.dsfielddictionary.dsSupplementalCredentialsIndex]
        if self.SupplementalCredentials != "":
            tmp = unhexlify(self.SupplementalCredentials[16:])
            tmpdec = dsDecryptWithPEK(ntds.dsfielddictionary.dsPEK, tmp)
            return dsSupplCredentials(tmpdec)
        else:
            return None
    
    def getSAMAccountType(self):
        if self.SAMAccountType != -1:
            if self.SAMAccountType & int("0x30000001", 16) == int("0x30000001", 16):
                return "SAM_MACHINE_ACCOUNT"
            if self.SAMAccountType & int("0x30000002", 16) == int("0x30000002", 16):
                return "SAM_TRUST_ACCOUNT"
            if self.SAMAccountType & int("0x30000000", 16) == int("0x30000000", 16):
                return "SAM_NORMAL_USER_ACCOUNT"
            if self.SAMAccountType & int("0x10000001", 16) == int("0x10000001", 16):
                return "SAM_NON_SECURITY_GROUP_OBJECT"
            if self.SAMAccountType & int("0x10000000", 16) == int("0x10000000", 16):
                return "SAM_GROUP_OBJECT"
            if self.SAMAccountType & int("0x20000001", 16) == int("0x20000001", 16):
                return "SAM_NON_SECURITY_ALIAS_OBJECT"
            if self.SAMAccountType & int("0x20000000", 16) == int("0x20000000", 16):
                return "SAM_ALIAS_OBJECT"
            if self.SAMAccountType & int("0x40000001", 16) == int("0x40000001", 16):
                return "SAM_APP_QUERY_GROUP"
            if self.SAMAccountType & int("0x40000000", 16) == int("0x40000000", 16):
                return "SAM_APP_BASIC_GROUP"
        else:
            return ""

    def getUserAccountControl(self):
        uac = []
        if self.UserAccountControl != -1:
            if self.UserAccountControl & int("0x1", 16) == int("0x1", 16):
                uac.append("SCRIPT")
            if self.UserAccountControl & int("0x2", 16) == int("0x2", 16):
                uac.append("ACCOUNTDISABLE")
            if self.UserAccountControl & int("0x8", 16) == int("0x8", 16):
                uac.append("HOMEDIR_REQUIRED")
            if self.UserAccountControl & int("0x10", 16) == int("0x10", 16):
                uac.append("LOCKOUT")
            if self.UserAccountControl & int("0x20", 16) == int("0x20", 16):
                uac.append("PWD_NOTREQD")
            if self.UserAccountControl & int("0x40", 16) == int("0x40", 16):
                uac.append("PASSWD_CANT_CHANGE")
            if self.UserAccountControl & int("0x80", 16)== int("0x80", 16):
                uac.append("ENCRYPTED_TEXT_PWD_ALLOWED")
            if self.UserAccountControl & int("0x200", 16) == int("0x200", 16):
                uac.append("NORMAL_ACCOUNT")
            if self.UserAccountControl & int("0x800", 16) == int("0x800", 16) :
                uac.append("INTERDOMAIN_TRUST_ACCOUNT")
            if self.UserAccountControl & int("0x1000", 16) == int("0x1000", 16):
                uac.append("WORKSTATION_TRUST_ACCOUNT")
            if self.UserAccountControl & int("0x2000", 16) == int("0x2000", 16):
                uac.append("SERVER_TRUST_ACCOUNT")
            if self.UserAccountControl & int("0x10000", 16) == int("0x10000", 16):
                uac.append("DONT_EXPIRE_PASSWORD")
            if self.UserAccountControl & int("0x40000", 16) == int("0x40000", 16):
                uac.append("SMARTCARD_REQUIRED")
            if self.UserAccountControl & int("0x80000", 16) == int("0x80000", 16):
                uac.append("TRUSTED_FOR_DELEGATION")
            if self.UserAccountControl & int("0x100000", 16) == int("0x100000", 16):
                uac.append("NOT_DELEGATED")
            if self.UserAccountControl & int("0x200000", 16) == int("0x200000", 16):
                uac.append("USE_DES_KEY_ONLY")
            if self.UserAccountControl & int("0x400000", 16) == int("0x400000", 16):
                uac.append("DONT_REQ_PREAUTH")
            if self.UserAccountControl & int("0x800000", 16) == int("0x800000", 16):
                uac.append("PASSWORD_EXPIRED")
            if self.UserAccountControl & int("0x1000000", 16) == int("0x1000000", 16):
                uac.append("TRUSTED_TO_AUTH_FOR_DELEGATION")
        return uac
    
    def getMemberOf(self):
        grouplist = []
        try:
            grouplist = dsMapBackwardLinks[self.RecordId]
            return grouplist
        except KeyError:
            return []
        

class dsUser(dsAccount):
    '''
    The class used for representing User objects stored in AD
    '''
    Certificate = ""
    
    def __init__(self, dsDatabase, dsRecordId):
        '''
        Constructor
        '''
        dsAccount.__init__(self, dsDatabase, dsRecordId)
        if self.Record[ntds.dsfielddictionary.dsADUserObjectsIndex] != "":
            self.Certificate = unhexlify(self.Record[ntds.dsfielddictionary.dsADUserObjectsIndex])
    
    def __str__(self):
        tmpStr = ""
        tmpStr += "\nRecord ID:            %d" % self.RecordId
        tmpStr += "\nUser name:            %s" % self.Name
        tmpStr += "\nUser principal name:  %s" % self.PrincipalName
        tmpStr += "\nSAM Account name:     %s" % self.SAMAccountName
        tmpStr += "\nSAM Account type:     %s" % self.getSAMAccountType()
        tmpStr += "\nGUID:                 %s" % str(self.GUID)
        tmpStr += "\nSID:                  %s" % str(self.SID)
        tmpStr += "\nWhen created:         %s" % dsGetDSTimeStampStr(self.WhenCreated)
        tmpStr += "\nWhen changed:         %s" % dsGetDSTimeStampStr(self.WhenChanged)
        tmpStr += "\nAccount expires:      %s" % dsGetDSTimeStampStr(self.AccountExpires)
        tmpStr += "\nPassword last set:    %s" % dsGetDSTimeStampStr(self.PasswordLastSet)
        tmpStr += "\nLast logon:           %s" % dsGetDSTimeStampStr(self.LastLogon)
        tmpStr += "\nLast logon timestamp: %s" % dsGetDSTimeStampStr(self.LastLogonTimeStamp)
        tmpStr += "\nBad password time     %s" % dsGetDSTimeStampStr(self.BadPwdTime)
        tmpStr += "\nLogon count:          %d" % self.LogonCount
        tmpStr += "\nBad password count:   %d" % self.BadPwdCount
        if self.DialInAccessPermission == -1:
            tmpStr += "\nDial-In access perm:  Controlled by policy"
        elif self.DialInAccessPermission == 1:
            tmpStr += "\nDial-In access perm:  Allow access"
        elif self.DialInAccessPermission == 0:
            tmpStr += "\nDial-In access perm:  Deny access"
        
        tmpStr += "\nUser Account Control:"
        for uac in self.getUserAccountControl():
            tmpStr += "\n\t%s" % uac
        
        tmpStr += "\nAncestors:\n\t"
        ancestors = self.getAncestors(self.DB)
        i = 0
        for ancestor in ancestors:
            if i < len(ancestors)-1:
                tmpStr += "%s, " % ancestor.Name
            else:
                tmpStr += "%s" % ancestor.Name
            i += 1
            
        return tmpStr
        
class dsComputer(dsAccount):
    '''
    The class used for representing Computer objects stored in AD
    '''
    DNSHostName = ""
    OSName = ""
    OSVersion = ""

    def __init__(self, dsDatabase, dsRecordId):
        '''
        Constructor
        '''
        dsAccount.__init__(self, dsDatabase, dsRecordId)
        self.DNSHostName = self.Record[ntds.dsfielddictionary.dsDNSHostNameIndex]
        self.OSName = self.Record[ntds.dsfielddictionary.dsOSNameIndex]
        self.OSVersion = self.Record[ntds.dsfielddictionary.dsOSVersionIndex]
    
    def getRecoveryInformations(self, dsDatabase):
        rinfos = []
        childlist = self.getChilds()
        for child in childlist:
            if dsGetRecordType(dsDatabase, child) == dsGetTypeIdByTypeName(dsDatabase, "ms-FVE-RecoveryInformation"):
                rinfos.append(dsFVERecoveryInformation(dsDatabase, child))
        return rinfos
    
    def __str__(self):
        tmpStr = ""
        tmpStr += "\nRecord ID:            %d" % self.RecordId
        tmpStr += "\nComputer name:        %s" % self.Name
        tmpStr += "\nDNS name:             %s" % self.DNSHostName
        tmpStr += "\nGUID:                 %s" % str(self.GUID)
        tmpStr += "\nSID:                  %s" % str(self.SID)
        tmpStr += "\nOS name:              %s" % self.OSName
        tmpStr += "\nOS version:           %s" % self.OSVersion
        tmpStr += "\nWhen created:         %s" % dsGetDSTimeStampStr(self.WhenCreated)
        tmpStr += "\nWhen changed:         %s" % dsGetDSTimeStampStr(self.WhenChanged)
        if self.DialInAccessPermission == -1:
            tmpStr += "\nDial-In access perm:  Controlled by policy"
        elif self.DialInAccessPermission == 1:
            tmpStr += "\nDial-In access perm:  Allow access"
        elif self.DialInAccessPermission == 0:
            tmpStr += "\nDial-In access perm:  Deny access"
        
        tmpStr += "\nAncestors:\n\t"
        for ancestor in self.getAncestors(self.DB):
            tmpStr += "%s " % ancestor.Name
            
        return tmpStr
    
class dsGroup(dsObject):
    '''
    The class used for representing Group objects stored in AD
    '''
    SID     = None
    
    def __init__(self, dsDatabase, dsRecordId):
        '''
        Constructor
        '''
        dsObject.__init__(self, dsDatabase, dsRecordId)
        self.SID = SID(self.Record[ntds.dsfielddictionary.dsSIDIndex])
    
    def getMembers(self):
        memberlist = []
        try:
            memberlist = dsMapLinks[self.RecordId]
            return memberlist
        except KeyError:
            return []

class dsKerberosKey:
    IterationCount = None
    # for list of encryption codes see NTSecAPI.h header in Microsoft SDK
    # normally you'll see the following codes:
    #define KERB_ETYPE_DES_CBC_MD5      3
    #define KERB_ETYPE_AES128_CTS_HMAC_SHA1_96    17
    #define KERB_ETYPE_AES256_CTS_HMAC_SHA1_96    18
    #define KERB_ETYPE_RC4_PLAIN        -140
    KeyType = None
    Key = None
    
class dsKerberosNewKeys:
    DefaultSalt = None
    Credentials = None
    OldCredentials = None
    OlderCredentials = None
    def __init__(self):
        self.Credentials = []
        self.OldCredentials = []
        self.OlderCredentials = []
        
    def Print(self, indent=""):
        print "{0}salt: {1}".format(indent, self.DefaultSalt)
        if len(self.Credentials) > 0:
            print "{0}Credentials".format(indent)
            for key in self.Credentials:
                print "{0}  {1} {2}".format(indent, key.KeyType, hexlify(key.Key))
        if len(self.OldCredentials) > 0:
            print "{0}OldCredentials".format(indent)
            for key in self.OldCredentials:
                print "{0}  {1} {2}".format(indent, key.KeyType, hexlify(key.Key))
        if len(self.OlderCredentials) > 0:
            print "{0}OlderCredentials".format(indent)
            for key in self.OlderCredentials:
                print "{0}  {1} {2}".format(indent, key.KeyType, hexlify(key.Key))

class dsSupplCredentials:
    '''
    Supplemental credentials structures are documented in
    http://msdn.microsoft.com/en-us/library/cc245499.aspx
    '''
    def __init__(self, text):
        self.KerberosNewerKeys = None
        self.KerberosKeys = None
        self.WDigestHashes = None
        self.Packages = None
        self.Password = None
        self.Text = text
        self.ParseUserProperties(text)
    
    def Print(self, indent=""):
        if self.KerberosNewerKeys != None:
            print "{0}Kerberos newer keys".format(indent)
            self.KerberosNewerKeys.Print(indent + "  ")
        if self.KerberosKeys != None:
            print "{0}Kerberos keys".format(indent)
            self.KerberosKeys.Print(indent + "  ")
        if self.WDigestHashes != None:
            print "{0}WDigest hashes".format(indent)
            for h in self.WDigestHashes:
                print "{0}  {1}".format(indent, hexlify(h))
        if self.Packages != None:
            print "{0}Packages".format(indent)
            for p in self.Packages:
                print "{0}  {1}".format(indent, p)
        if self.Password != None:
            print "{0}Password: {1}".format(indent, self.Password)
        print "Debug: "
        print dump(self.Text,16,16)
    
    def ParseUserProperties(self, text):
        offset = 0
        if len(text[offset:offset+4]) != 4:
            return
        reserved1 = unpack('I', text[offset:offset+4])[0]
        assert reserved1 == 0
#        print "reserved1: " + str(reserved1)
        
        offset += 4
        if len(text[offset:offset+4]) != 4:
            return
        lengthOfStructure = unpack('I', text[offset:offset+4])[0]
        assert len(text) == lengthOfStructure + 3*4 + 1
#        print "lengthOfStructure: " + str(lengthOfStructure)
        
        offset += 4
        if len(text[offset:offset+2]) != 2:
            return
        reserved2 = unpack('H', text[offset:offset+2])[0]
        assert reserved2 == 0
#        print "reserved2: " + str(reserved2)
        
        offset += 2
        if len(text[offset:offset+2]) != 2:
            return
        reserved3 = unpack('H', text[offset:offset+2])[0]
        assert reserved3 == 0
#        print "reserved3: " + str(reserved3)
        
        offset += 2
        offset += 96 # reserved4
        if len(text[offset:offset+2]) < 2:
            return
        PropertySignature = unpack('H', text[offset:offset+2])[0]
        assert PropertySignature == 0x50
#        print "PropertySignature: " + str(PropertySignature)
        
        offset += 2
        if len(text[offset:offset+2]) < 2:
            return
        # The number of USER_PROPERTY elements in the UserProperties field.
        PropertyCount = unpack('H', text[offset:offset+2])[0]
#        print "PropertyCount: " + str(PropertyCount)
        
        offset += 2
        for i in range(PropertyCount):
            offset = self.ParseUserProperty(text, offset)
        assert offset == len(text) - 1
        reserved5 = ord(text[offset:offset+1])
        # must be 0 according to documentation, but in practice contains arbitrary value
        #assert reserved5 == 0
  
    def ParseUserProperty(self, text, offset):
        if len(text[offset:offset+2]) != 2:
            return
        NameLength = unpack('H', text[offset:offset+2])[0]
        offset += 2
        if len(text[offset:offset+2]) != 2:
            return
        ValueLength = unpack('H', text[offset:offset+2])[0]
        
        offset += 2
        if len(text[offset:offset+2]) != 2:
            return
        reserved = unpack('H', text[offset:offset+2])[0]
        
        offset += 2
        if len(text[offset:offset+2]) != 2:
            return
        Name = text[offset:offset+NameLength].decode('utf-16')
        
        offset += NameLength
        if len(text[offset:offset+ValueLength]) != ValueLength:
            return
        if Name == u"Primary:Kerberos-Newer-Keys":
            self.KerberosNewerKeys = self.ParseKerberosNewerKeysPropertyValue(unhexlify(text[offset:offset+ValueLength]))
        elif Name == u"Primary:Kerberos":
            self.KerberosKeys = self.ParseKerberosPropertyValue(unhexlify(text[offset:offset+ValueLength]))
        elif Name == u"Primary:WDigest":
            self.WDigestHashes = self.ParseWDigestPropertyValue(unhexlify(text[offset:offset+ValueLength]))
        elif Name == u"Packages":
            self.Packages = unhexlify(text[offset:offset+ValueLength]).decode('utf-16').split("\x00")
        elif Name == u"Primary:CLEARTEXT":
            try:
                self.Password = unicode(unhexlify(text[offset:offset+ValueLength]).decode('utf-16')).encode('utf8')
            except:
                self.Password = dump(unhexlify(text[offset:offset+ValueLength]),16,16)
        else:
            print Name
        return offset + ValueLength

    def ParseWDigestPropertyValue(self, text):
        try:
            offset = 0
            Reserved1 = ord(text[offset:offset+1])
            offset += 1
            Reserved2 = ord(text[offset:offset+1])
            assert Reserved2 == 0
            offset += 1
            Version = ord(text[offset:offset+1])
            assert Version == 1
            offset += 1
            NumberOfHashes = ord(text[offset:offset+1])
            assert NumberOfHashes == 29
            offset += 1
            for i in range(3):
                Reserved3 = unpack('I', text[offset:offset+4])[0]
                assert Reserved3 == 0
                offset += 4
            hashes = []
            for i in range(NumberOfHashes):
                hashes.append(text[offset:offset+16])
                offset += 16
            return hashes
        except:
            return None
    
    def ParseKerberosNewerKeysPropertyValue(self, text):
        try:
            keys = dsKerberosNewKeys()
            
            offset = 0
            Revision = unpack('H', text[offset:offset+2])[0]
            assert Revision == 4

            offset += 2
            Flags = unpack('H', text[offset:offset+2])[0]
            assert Flags == 0

            offset += 2
            CredentialCount = unpack('H', text[offset:offset+2])[0]

            offset += 2
            ServiceCredentialCount = unpack('H', text[offset:offset+2])[0]
            assert ServiceCredentialCount == 0

            offset += 2
            OldCredentialCount = unpack('H', text[offset:offset+2])[0]

            offset += 2
            OlderCredentialCount = unpack('H', text[offset:offset+2])[0]

            offset += 2
            DefaultSaltLength = unpack('H', text[offset:offset+2])[0]

            offset += 2
            DefaultSaltMaximumLength = unpack('H', text[offset:offset+2])[0]

            offset += 2
            DefaultSaltOffset = unpack('I', text[offset:offset+4])[0]

            offset += 4
            DefaultIterationCount = unpack('I', text[offset:offset+4])[0]

            offset += 4
            for i in range(CredentialCount):
                offset, key = self.KerberosKeyDataNew(text, offset)
                keys.Credentials.append(key)
            for i in range(OldCredentialCount):
                offset, key = self.KerberosKeyDataNew(text, offset)
                keys.OldCredentials.append(key)
            for i in range(OlderCredentialCount):
                offset, key = self.KerberosKeyDataNew(text, offset)
                keys.OlderCredentials.append(key)

            # + one blank KeyDataNew record. Record length is 24 bytes,
            offset += 24
            assert offset == DefaultSaltOffset
            keys.DefaultSalt = text[offset:offset+DefaultSaltMaximumLength].decode("utf-16")

            return keys
        except:
            return None

    def ParseKerberosPropertyValue(self, text):
        try:
            keys = dsKerberosNewKeys()
            
            offset = 0
            Revision = unpack('H', text[offset:offset+2])[0]
#            print "Revision: " + str(Revision)
            assert Revision == 3

            offset += 2
            Flags = unpack('H', text[offset:offset+2])[0]
#            print "Flags: " + str(Flags)
            assert Flags == 0

            offset += 2
            CredentialCount = unpack('H', text[offset:offset+2])[0]
#            print "CredentialCount: " + str(CredentialCount)

            offset += 2
            OldCredentialCount = unpack('H', text[offset:offset+2])[0]
#            print "OldCredentialCount: " + str(OldCredentialCount)

            offset += 2
            DefaultSaltLength = unpack('H', text[offset:offset+2])[0]
#            print "DefaultSaltLength: " + str(DefaultSaltLength)

            offset += 2
            DefaultSaltMaximumLength = unpack('H', text[offset:offset+2])[0]
#            print "DefaultSaltMaximumLength: " + str(DefaultSaltMaximumLength)

            offset += 2
            DefaultSaltOffset = unpack('I', text[offset:offset+4])[0]
#            print "DefaultSaltOffset: " + str(DefaultSaltOffset)

            offset += 4
            for i in range(CredentialCount):
                offset, key = self.KerberosKeyData(text, offset)
                keys.Credentials.append(key)
            for i in range(OldCredentialCount):
                offset, key = self.KerberosKeyData(text, offset)
                keys.OldCredentials.append(key)

            # + one blank KeyDataNew record. Record length is 20 bytes,
            offset += 20
            #assert offset == DefaultSaltOffset
            #keys.DefaultSalt = text[offset:offset+DefaultSaltMaximumLength].decode("utf-16")
            keys.DefaultSalt = text[DefaultSaltOffset:DefaultSaltOffset+DefaultSaltMaximumLength].decode("utf-16")
            return keys
        except:
               return None

    def KerberosKeyDataNew(self, text, offset):
        try:
            key = dsKerberosKey()
            Reserved1 = unpack('H', text[offset:offset+2])[0]
            assert Reserved1 == 0
            offset += 2
            Reserved2 = unpack('H', text[offset:offset+2])[0]
            assert Reserved2 == 0
            offset += 2
            Reserved3 = unpack('I', text[offset:offset+4])[0]
            assert Reserved3 == 0
            offset += 4
            key.IterationCount = unpack('I', text[offset:offset+4])[0]
            offset += 4
            key.KeyType = unpack('i', text[offset:offset+4])[0]
            offset += 4
            KeyLength = unpack('I', text[offset:offset+4])[0]
            offset += 4
            KeyOffset = unpack('I', text[offset:offset+4])[0]
            offset += 4
            key.Key = text[KeyOffset:KeyOffset+KeyLength]
            return offset, key
        except:
            return None
    
    def KerberosKeyData(self, text, offset):
        try:
            key = dsKerberosKey()
            Reserved1 = unpack('H', text[offset:offset+2])[0]
#            print "Reserved1: " + str(Reserved1)
            assert Reserved1 == 0
            
            offset += 2
            Reserved2 = unpack('H', text[offset:offset+2])[0]
#            print "Reserved2: " + str(Reserved2)
            assert Reserved2 == 0
            
            offset += 2
            Reserved3 = unpack('I', text[offset:offset+4])[0]
#            print "Reserved3: " + str(Reserved3)
            assert Reserved3 == 0
            
            offset += 4
            key.KeyType = unpack('i', text[offset:offset+4])[0]
#            print "KeyType: " + str(key.KeyType)
            
            offset += 4
            KeyLength = unpack('I', text[offset:offset+4])[0]
#            print "KeyLength: " + str(KeyLength)
            
            offset += 4
            KeyOffset = unpack('I', text[offset:offset+4])[0]
#            print "KeyOffset: " + str(KeyOffset)
            
            offset += 4
            key.Key = text[KeyOffset:KeyOffset+KeyLength]
#            print "Key: " + str(hexlify(key.Key))
            return offset, key
        except:
            return None
