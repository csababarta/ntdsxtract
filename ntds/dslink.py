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
from ntds.dstime import *
import sys
from lib.map import *
import pickle
from os import path

dsMapLinks         = {}
dsMapBackwardLinks = {}

def dsInitLinks(dsESEFile, workdir):
    dl = open(dsESEFile , 'rb', 0)
    dl.seek(0)
    line = dl.readline()
    if line == "":
        sys.stderr.write("[-] Warning! Error processing the first line!\n")
        sys.exit(1)
    else:
        ntds.dsfielddictionary.dsFieldNameRecord = line.split('\t')
        record = line.split('\t')
        for cid in range(0, len(record)-1):
#------------------------------------------------------------------------------ 
# filling indexes for membership attributes
#------------------------------------------------------------------------------ 
            if (record[cid] == "link_DNT"):
                ntds.dsfielddictionary.dsTargetRecordIdIndex = cid
            if (record[cid] == "backlink_DNT"):
                ntds.dsfielddictionary.dsSourceRecordIdIndex = cid
            if (record[cid] == "link_deltime"):
                ntds.dsfielddictionary.dsLinkDeleteTimeIndex = cid
    dl.seek(0)
    dsCheckMaps(dl, workdir)
    #dsBuildLinkMaps(dl)

def dsCheckMaps(dsDatabase, workdir): 
    try:
        global dsMapLinks
        global dsMapBackwardLinks

        sys.stderr.write("[+] Loading saved map files (Stage 2)...\n")
        dsLoadMap(path.join(workdir, "links.map"), dsMapLinks)
        dsLoadMap(path.join(workdir, "backlinks.map"), dsMapBackwardLinks)
        
    except Exception as e:
        sys.stderr.write("[!] Warning: Opening saved maps failed: " + str(e) + "\n")
        sys.stderr.write("[+] Rebuilding maps...\n")
        dsBuildLinkMaps(dsDatabase, workdir)
        pass

def dsBuildLinkMaps(dsLinks, workdir):
    global dsMapLinks
    global dsMapBackwardLinks
    
    sys.stderr.write("[+] Extracting object links...\n")
    sys.stderr.flush()
    lineid = 0
    while True:
        line = dsLinks.readline()
        if line == "":
            break
        record = line.split('\t')
        if lineid != 0:
            source = int(record[ntds.dsfielddictionary.dsSourceRecordIdIndex])
            target = int(record[ntds.dsfielddictionary.dsTargetRecordIdIndex])
            
            deltime = -1
            if record[ntds.dsfielddictionary.dsLinkDeleteTimeIndex] != "":
                deltime = dsVerifyDSTime(record[ntds.dsfielddictionary.dsLinkDeleteTimeIndex])
                
            try: 
                tmp = dsMapLinks[target]
            except KeyError:
                dsMapLinks[target] = []
                pass
            
            try:
                dsMapLinks[target].append((source, deltime))
            except KeyError:
                dsMapLinks[target] = []
                dsMapLinks[target].append((source, deltime))
           
            
            try: 
                tmp = dsMapBackwardLinks[source]
            except KeyError:
                dsMapBackwardLinks[source] = []
                pass
            
            try:
                dsMapBackwardLinks[source].append((target, deltime))
            except KeyError:
                dsMapBackwardLinks[source] = []
                dsMapBackwardLinks[source].append((target, deltime))
        lineid += 1
    
    links = open(path.join(workdir, "links.map"), "wb")
    pickle.dump(dsMapLinks, links)
    links.close()
    
    backlinks = open(path.join(workdir, "backlinks.map"), "wb")
    pickle.dump(dsMapBackwardLinks, backlinks)
    backlinks.close()
