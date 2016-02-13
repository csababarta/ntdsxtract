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
from stat import *
from os import stat
from os import path
import time
import ntds.dsfielddictionary
from ntds.dsencryption import *
from lib.map import *
from lib.sid import *
from lib.guid import *
import pickle

dsMapOffsetByLineId   = {} #Map that can be used to find the offset for line
dsMapLineIdByRecordId = {} #Map that can be used to find the line for record
dsMapTypeByRecordId   = {} #Map that can be used to find the type for record
dsMapRecordIdByName   = {} #Map that can be used to find the record for name
dsMapChildsByRecordId = {} #Map that can be used to find child objects
dsMapTypeIdByTypeName = {} #Map that can be used to find child objects
dsMapRecordIdByTypeId = {} #Map that can be used to find all the records that have a type
dsMapRecordIdBySID    = {} #Map that can be used to find the record for a SID
dsMapRecordIdByGUID   = {} #Map that can be used to find the record for a GUID

dsSchemaTypeId = -1

dsDatabaseSize = -1

def dsInitDatabase(dsESEFile, workdir):
    global dsDatabaseSize
    dsDatabaseSize = stat(dsESEFile).st_size
    sys.stderr.write("\n[+] Initialising engine...\n")  
    db = open(dsESEFile , 'rb', 0)
    db.seek(0)
    line = db.readline()
    if line == "":
        sys.stderr.write("[!] Warning! Error processing the first line!\n")
        sys.exit(1)
    else:
        dsFieldNameRecord = line.split('\t')
        record = line.split('\t')
        for cid in range(0, len(record)-1):
#------------------------------------------------------------------------------ 
# filling indexes for object attributes
#------------------------------------------------------------------------------ 
            if (record[cid] == "DNT_col"):
                ntds.dsfielddictionary.dsRecordIdIndex = cid
            if (record[cid] == "PDNT_col"):
                ntds.dsfielddictionary.dsParentRecordIdIndex = cid
            if (record[cid] == "time_col"):
                ntds.dsfielddictionary.dsRecordTimeIndex = cid
            if (record[cid] == "Ancestors_col"):
                ntds.dsfielddictionary.dsAncestorsIndex = cid
            if (record[cid] == "ATTb590606"):
                ntds.dsfielddictionary.dsObjectTypeIdIndex = cid
            if (record[cid] == "ATTm3"):
                ntds.dsfielddictionary.dsObjectNameIndex = cid
            if (record[cid] == "ATTm589825"):
                ntds.dsfielddictionary.dsObjectName2Index = cid
            if (record[cid] == "ATTk589826"):
                ntds.dsfielddictionary.dsObjectGUIDIndex = cid
            if (record[cid] == "ATTl131074"):
                ntds.dsfielddictionary.dsWhenCreatedIndex = cid
            if (record[cid] == "ATTl131075"):
                ntds.dsfielddictionary.dsWhenChangedIndex = cid
            if (record[cid] == "ATTq131091"):
                ntds.dsfielddictionary.dsUSNCreatedIndex = cid
            if (record[cid] == "ATTq131192"):
                ntds.dsfielddictionary.dsUSNChangedIndex = cid
            if (record[cid] == "OBJ_col"):
                ntds.dsfielddictionary.dsObjectColIndex = cid
            if (record[cid] == "ATTi131120"):
                ntds.dsfielddictionary.dsIsDeletedIndex = cid
#------------------------------------------------------------------------------ 
# Filling indexes for deleted object attributes
#------------------------------------------------------------------------------ 
            if (record[cid] == "ATTb590605"):
                ntds.dsfielddictionary.dsOrigContainerIdIndex = cid
#------------------------------------------------------------------------------ 
# Filling indexes for account object attributes
#------------------------------------------------------------------------------ 
            if (record[cid] == "ATTr589970"):
                ntds.dsfielddictionary.dsSIDIndex = cid
            if (record[cid] == "ATTm590045"):
                ntds.dsfielddictionary.dsSAMAccountNameIndex = cid
            if (record[cid] == "ATTm590480"):
                ntds.dsfielddictionary.dsUserPrincipalNameIndex = cid
            if (record[cid] == "ATTj590126"):
                ntds.dsfielddictionary.dsSAMAccountTypeIndex = cid
            if (record[cid] == "ATTj589832"):
                ntds.dsfielddictionary.dsUserAccountControlIndex = cid
            if (record[cid] == "ATTq589876"):
                ntds.dsfielddictionary.dsLastLogonIndex = cid
            if (record[cid] == "ATTq591520"):
                ntds.dsfielddictionary.dsLastLogonTimeStampIndex = cid
            if (record[cid] == "ATTq589983"):
                ntds.dsfielddictionary.dsAccountExpiresIndex = cid
            if (record[cid] == "ATTq589920"):
                ntds.dsfielddictionary.dsPasswordLastSetIndex = cid
            if (record[cid] == "ATTq589873"):
                ntds.dsfielddictionary.dsBadPwdTimeIndex = cid
            if (record[cid] == "ATTj589993"):
                ntds.dsfielddictionary.dsLogonCountIndex = cid
            if (record[cid] == "ATTj589836"):
                ntds.dsfielddictionary.dsBadPwdCountIndex = cid
            if (record[cid] == "ATTj589922"):
                ntds.dsfielddictionary.dsPrimaryGroupIdIndex = cid
            if (record[cid] == "ATTk589914"):    
                ntds.dsfielddictionary.dsNTHashIndex = cid
            if (record[cid] == "ATTk589879"):
                ntds.dsfielddictionary.dsLMHashIndex = cid
            if (record[cid] == "ATTk589918"):
                ntds.dsfielddictionary.dsNTHashHistoryIndex = cid
            if (record[cid] == "ATTk589984"):
                ntds.dsfielddictionary.dsLMHashHistoryIndex = cid
            if (record[cid] == "ATTk591734"):
                ntds.dsfielddictionary.dsUnixPasswordIndex = cid
            if (record[cid] == "ATTk36"):
                ntds.dsfielddictionary.dsADUserObjectsIndex = cid
            if (record[cid] == "ATTk589949"):
                ntds.dsfielddictionary.dsSupplementalCredentialsIndex = cid
#------------------------------------------------------------------------------
# Filling indexes for computer objects attributes
#------------------------------------------------------------------------------
            if (record[cid] == "ATTj589993"):
                ntds.dsfielddictionary.dsLogonCountIndex = cid
            if (record[cid] == "ATTm590443"):
                ntds.dsfielddictionary.dsDNSHostNameIndex = cid
            if (record[cid] == "ATTm590187"):
                ntds.dsfielddictionary.dsOSNameIndex = cid
            if (record[cid] == "ATTm590188"):
                ntds.dsfielddictionary.dsOSVersionIndex = cid
#------------------------------------------------------------------------------ 
# Filling indexes for bitlocker objects
#------------------------------------------------------------------------------ 
            if (record[cid] == "ATTm591788"):
                ntds.dsfielddictionary.dsRecoveryPasswordIndex = cid
            if (record[cid] == "ATTk591823"):
                ntds.dsfielddictionary.dsFVEKeyPackageIndex = cid
            if (record[cid] == "ATTk591822"):
                ntds.dsfielddictionary.dsVolumeGUIDIndex = cid
            if (record[cid] == "ATTk591789"):
                ntds.dsfielddictionary.dsRecoveryGUIDIndex = cid
#------------------------------------------------------------------------------ 
# Filling indexes for bitlocker objects
#------------------------------------------------------------------------------ 
            if (record[cid] == "ATTi590943"):
                ntds.dsfielddictionary.dsDialInAccessPermission = cid
#===============================================================================
# Filling indexes for AD encryption
#===============================================================================
            if (record[cid] == "ATTk590689"):
                ntds.dsfielddictionary.dsPEKIndex = cid
    db.seek(0)
    dsCheckMaps(db, workdir)
    return db

def dsCheckMaps(dsDatabase, workdir):
    try:
        global dsMapOffsetByLineId
        global dsMapLineIdByRecordId
        global dsMapRecordIdByName
        global dsMapTypeByRecordId
        global dsMapChildsByRecordId
        global dsMapTypeIdByTypeName
        global dsMapRecordIdByTypeId
        global dsMapRecordIdBySID
        global dsMapRecordIdByGUID

        sys.stderr.write("[+] Loading saved map files (Stage 1)...\n")
        dsLoadMap(path.join(workdir, "offlid.map"), dsMapOffsetByLineId)
        dsLoadMap(path.join(workdir, "lidrid.map"), dsMapLineIdByRecordId)
        dsLoadMap(path.join(workdir, "ridname.map"), dsMapRecordIdByName)
        dsLoadMap(path.join(workdir, "typerid.map"), dsMapTypeByRecordId)
        dsLoadMap(path.join(workdir, "childsrid.map"), dsMapChildsByRecordId)
        dsLoadMap(path.join(workdir, "typeidname.map"), dsMapTypeIdByTypeName)
        dsLoadMap(path.join(workdir, "ridsid.map"), dsMapRecordIdBySID)
        dsLoadMap(path.join(workdir, "ridguid.map"), dsMapRecordIdByGUID)
        dsLoadMap(path.join(workdir, "ridtype.map"), dsMapRecordIdByTypeId)
        
        pek = open(path.join(workdir, "pek.map"), "rb")
        ntds.dsfielddictionary.dsEncryptedPEK = pek.read()
        pek.close()
        
    except Exception as e:
        sys.stderr.write("[!] Warning: Opening saved maps failed: " + str(e) + "\n")
        sys.stderr.write("[+] Rebuilding maps...\n")
        dsBuildMaps(dsDatabase, workdir)
        pass

def dsBuildMaps(dsDatabase, workdir):
    
    global dsMapOffsetByLineId
    global dsMapLineIdByRecordId
    global dsMapRecordIdByName
    global dsMapTypeByRecordId
    global dsMapChildsByRecordId
    global dsMapRecordIdBySID
    global dsMapRecordIdbyGUID
    global dsSchemaTypeId
        
    lineid = 0
    while True:
        sys.stderr.write("\r[+] Scanning database - %d%% -> %d records processed" % (
                                            dsDatabase.tell()*100/dsDatabaseSize,
                                            lineid+1
                                            ))
        sys.stderr.flush()
        try:
            dsMapOffsetByLineId[lineid] = dsDatabase.tell()
        except:
            sys.stderr.write("\n[!] Warning! Error at dsMapOffsetByLineId!\n")
            pass
        line = dsDatabase.readline()
        if line == "":
            break
        record = line.split('\t')
        if lineid != 0:
            #===================================================================
            # This record will always be the record representing the domain
            # object
            # This should be the only record containing the PEK
            #===================================================================
            if record[ntds.dsfielddictionary.dsPEKIndex] != "":
                if ntds.dsfielddictionary.dsEncryptedPEK != "":
                    sys.stderr.write("\n[!] Warning! Multiple records with PEK entry!\n")
                ntds.dsfielddictionary.dsEncryptedPEK = record[ntds.dsfielddictionary.dsPEKIndex]
                
            try:
                dsMapLineIdByRecordId[int(record[ntds.dsfielddictionary.dsRecordIdIndex])] = lineid
            except:
                sys.stderr.write("\n[!] Warning! Error at dsMapLineIdByRecordId!\n")
                pass
            
            try:
                tmp = dsMapRecordIdByName[record[ntds.dsfielddictionary.dsObjectName2Index]]
                # Also save the Schema type id for future use
                if record[ntds.dsfielddictionary.dsObjectName2Index] == "Schema":
                    if dsSchemaTypeId == -1 and record[ntds.dsfielddictionary.dsObjectTypeIdIndex] != "":
                        dsSchemaTypeId = int(record[ntds.dsfielddictionary.dsObjectTypeIdIndex])
                    else:
                        sys.stderr.write("\n[!] Warning! There is more than one Schema object! The DB is inconsistent!\n")
            except:
                dsMapRecordIdByName[record[ntds.dsfielddictionary.dsObjectName2Index]] = int(record[ntds.dsfielddictionary.dsRecordIdIndex])
                if record[ntds.dsfielddictionary.dsObjectName2Index] == "Schema":
                    if dsSchemaTypeId == -1 and record[ntds.dsfielddictionary.dsObjectTypeIdIndex] != "":
                        dsSchemaTypeId = int(record[ntds.dsfielddictionary.dsObjectTypeIdIndex])
                    else:
                        sys.stderr.write("\n[!] Warning! There is more than one Schema object! The DB is inconsistent!\n")
                pass
            
            try:
                dsMapTypeByRecordId[int(record[ntds.dsfielddictionary.dsRecordIdIndex])] = record[ntds.dsfielddictionary.dsObjectTypeIdIndex]
            except:
                sys.stderr.write("\n[!] Warning! Error at dsMapTypeByRecordId!\n")
                pass
            
            try:
                tmp = dsMapChildsByRecordId[int(record[ntds.dsfielddictionary.dsRecordIdIndex])]
            except KeyError:
                dsMapChildsByRecordId[int(record[ntds.dsfielddictionary.dsRecordIdIndex])] = []
                pass
            
            try:
                dsMapChildsByRecordId[int(record[ntds.dsfielddictionary.dsParentRecordIdIndex])].append(int(record[ntds.dsfielddictionary.dsRecordIdIndex]))
            except KeyError:
                dsMapChildsByRecordId[int(record[ntds.dsfielddictionary.dsParentRecordIdIndex])] = []
                dsMapChildsByRecordId[int(record[ntds.dsfielddictionary.dsParentRecordIdIndex])].append(int(record[ntds.dsfielddictionary.dsRecordIdIndex]))
            
            try:
                dsMapRecordIdBySID[str(SID(record[ntds.dsfielddictionary.dsSIDIndex]))]
            except KeyError:
            	dsMapRecordIdBySID[str(SID(record[ntds.dsfielddictionary.dsSIDIndex]))] = int(record[ntds.dsfielddictionary.dsRecordIdIndex])
            
            try:
                dsMapRecordIdByGUID[str(GUID(record[ntds.dsfielddictionary.dsObjectGUIDIndex]))]
            except KeyError:
            	dsMapRecordIdByGUID[str(GUID(record[ntds.dsfielddictionary.dsObjectGUIDIndex]))] = int(record[ntds.dsfielddictionary.dsRecordIdIndex])
            
            try:
            	if record[ntds.dsfielddictionary.dsObjectTypeIdIndex] != "":
                	dsMapRecordIdByTypeId[int(record[ntds.dsfielddictionary.dsObjectTypeIdIndex])].append(int(record[ntds.dsfielddictionary.dsRecordIdIndex]))
            except KeyError:
            	dsMapRecordIdByTypeId[int(record[ntds.dsfielddictionary.dsObjectTypeIdIndex])] = []
            	dsMapRecordIdByTypeId[int(record[ntds.dsfielddictionary.dsObjectTypeIdIndex])].append(int(record[ntds.dsfielddictionary.dsRecordIdIndex]))
                
        lineid += 1
    sys.stderr.write("\n")
    
    offlid = open(path.join(workdir, "offlid.map"), "wb")
    pickle.dump(dsMapOffsetByLineId, offlid)
    offlid.close()
    
    lidrid = open(path.join(workdir, "lidrid.map"), "wb")
    pickle.dump(dsMapLineIdByRecordId, lidrid)
    lidrid.close()
    
    ridname = open(path.join(workdir, "ridname.map"), "wb")
    pickle.dump(dsMapRecordIdByName, ridname)
    ridname.close()
    
    typerid = open(path.join(workdir, "typerid.map"), "wb")
    pickle.dump(dsMapTypeByRecordId, typerid)
    typerid.close()
    
    childsrid = open(path.join(workdir, "childsrid.map"), "wb")
    pickle.dump(dsMapChildsByRecordId, childsrid)
    childsrid.close()
    
    pek = open(path.join(workdir, "pek.map"), "wb")
    pek.write(ntds.dsfielddictionary.dsEncryptedPEK)
    pek.close()
    
    ridsid = open(path.join(workdir, "ridsid.map"), "wb")
    pickle.dump(dsMapRecordIdBySID, ridsid)
    ridsid.close()
    
    ridguid = open(path.join(workdir, "ridguid.map"), "wb")
    pickle.dump(dsMapRecordIdByGUID, ridguid)
    ridguid.close()
    
    ridtype = open(path.join(workdir, "ridtype.map"), "wb")
    pickle.dump(dsMapRecordIdByTypeId, ridtype)
    ridtype.close()
    
    dsBuildTypeMap(dsDatabase, workdir)

def dsBuildTypeMap(dsDatabase, workdir):
    global dsMapTypeIdByTypeName
    global dsMapLineIdByRecordId
    global dsMapChildsByRecordId
    global dsSchemaTypeId

    schemarecid  = -1
    
    sys.stderr.write("[+] Sanity checks...\n")
    
    if dsSchemaTypeId == -1:
    	sys.stderr.write("[!] Error! The Schema object's type id cannot be found! The DB is inconsistent!\n")
    	sys.exit(1)
    elif len(dsMapRecordIdByTypeId[dsSchemaTypeId]) > 1:
    	sys.stderr.write("[!] Warning! There are more than 1 schema objects! The DB is inconsistent!\n")
    	sys.stderr.write("      Schema record ids: " + str(dsMapRecordIdByTypeId[dsSchemaTypeId]) + "\n")
    	sys.stderr.write("      Please select the schema id you would like to use!\n")
    	tmp = raw_input()
    	while True:
    	    try:
    	        if int(tmp) in dsMapRecordIdByTypeId[dsSchemaTypeId]:
                    schemarecid = int(tmp)
                    break
                else:
                	sys.stderr.write("      Please enter a number that is in the list of ids!\n")
                	tmp = raw_input()
            except:
            	sys.stderr.write("      Please enter a number!\n")
            	tmp = raw_input()
    elif len(dsMapRecordIdByTypeId[dsSchemaTypeId]) == 0:
    	sys.stderr.write("[!] Warning! There is no schema object! The DB is inconsistent!\n")
    else:
    	schemarecid = dsMapRecordIdByTypeId[dsSchemaTypeId][0]
    
    sys.stderr.write("      Schema record id: %d\n" % schemarecid)
    sys.stderr.write("      Schema type id: %d\n" % int(dsMapTypeByRecordId[schemarecid]))
    sys.stderr.flush()

    schemachilds = dsMapChildsByRecordId[schemarecid]
    i = 0
    l = len(schemachilds)
    for child in schemachilds:
        sys.stderr.write("\r[+] Extracting schema information - %d%% -> %d records processed" % (
                                            i*100/l,
                                            i+1
                                            ))
        sys.stderr.flush()
        lineid = int(dsMapLineIdByRecordId[int(child)])
        offset = int(dsMapOffsetByLineId[int(lineid)])
        dsDatabase.seek(offset)
        
        record = ""
        line = ""
        line = dsDatabase.readline()
        if line != "":
            record = line.split('\t')
            name = record[ntds.dsfielddictionary.dsObjectName2Index]
            dsMapTypeIdByTypeName[name] = child
        i += 1
    
    typeidname = open(path.join(workdir, "typeidname.map"), "wb")
    pickle.dump(dsMapTypeIdByTypeName, typeidname)
    typeidname.close()
    
    sys.stderr.write("\r[+] Extracting schema information - %d%% -> %d records processed" % (
                                            100,
                                            i
                                            ))
    sys.stderr.write("\n")
    sys.stderr.flush()

def dsInitEncryption(syshive_fname):
    bootkey = get_syskey(syshive_fname)
    enc_pek = unhexlify(ntds.dsfielddictionary.dsEncryptedPEK[16:])
    ntds.dsfielddictionary.dsPEK=dsDecryptPEK(bootkey, enc_pek)
