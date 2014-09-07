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
from ntds.dsdatabase import *
import ntds.dsfielddictionary

def dsGetRecordByLineId(dsDatabase, dsLineId):
    '''
    Returns the parsed record for lineid by reading the appropriate line from
    the database
    '''
    offset = dsMapOffsetByLineId[int(dsLineId)]
    dsDatabase.seek(offset)
    line = dsDatabase.readline()
    if line == "":
        return None
    else:
        record = line.split('\t')
        return record

def dsGetRecordByRecordId(dsDatabase, dsRecordId):
    '''
    Returns the parsed record for recordid
    '''
    lineid = -1
    try:
        lineid = int(dsMapLineIdByRecordId[int(dsRecordId)])
        return dsGetRecordByLineId(dsDatabase, lineid)
    except:
        return None

def dsGetPreviousRecord(dsDatabase, dsRecordId):
    '''
    Returns the previous parsed record for recordid
    '''
    lineid = -1
    try:
        lineid = int(dsMapLineIdByRecordId[int(dsRecordId)])
        return dsGetRecordByLineId(dsDatabase, lineid - 1)
    except:
        return None

def dsGetNextRecord(dsDatabase, dsRecordId):
    '''
    Returns the next parsed record for recordid
    '''
    lineid = -1
    try:
        lineid = int(dsMapLineIdByRecordId[int(dsRecordId)])
        return dsGetRecordByLineId(dsDatabase, lineid + 1)
    except:
        return None

def dsGetRecordType(dsDatabase, dsRecordId):
    '''
    Returns the object type of the record
    '''
    typeid = -1
    try:
        typeid = int(dsMapTypeByRecordId[int(dsRecordId)])
        return typeid
    except:
        return -1

def dsGetTypeName(dsDatabase, dsTypeId):
    '''
    Returns the name of the object type
    '''
    name = ""
    try:
        record = dsGetRecordByRecordId(dsDatabase, int(dsTypeId))
        name = record[ntds.dsfielddictionary.dsObjectName2Index]
        return name    
    except:
        return ""

def dsGetTypeIdByTypeName(dsDatabase, dsTypeName):
    '''
    Returns the object type identified by the name
    '''
    TypeId = -1
    try:
        TypeId = int(dsMapTypeIdByTypeName[dsTypeName])
        return TypeId
    except:
        return -1
