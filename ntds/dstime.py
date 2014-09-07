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
import datetime
import time
import calendar
from struct import *

class dsUTC(datetime.tzinfo):
	def utcoffset(self, dt):
		return datetime.timedelta(hours=0)
	def dst(self, dt):
		return datetime.timedelta(0)
	def tzname(self,dt):
		return "UTC"

tzinfoUTC=dsUTC()
_FILETIME_null_date = datetime.datetime(1601, 1, 1, 0, 0, 0, tzinfo=tzinfoUTC)
_DBTIME_null_date = datetime.datetime(1900, 1, 1, 0, 0, 0, tzinfo=tzinfoUTC)

#_FILETIME_null_date = datetime.datetime(1601, 1, 1, 0, 0, 0)

#_DBTIME_null_date = datetime.datetime(1900, 1, 1, 0, 0, 0)



def dsVerifyDSTime(dsTime):
    if dsTime == "":
        return -1
    elif (int(dsTime) < 12000000000 or
          int(dsTime) >= 99999999999):
        return -1
    else:
        return int(dsTime)
    
def dsVerifyDSTimeStamp(dsTimeStamp):
    if dsTimeStamp == "":
        return -1
    elif (int(dsTimeStamp) < 120000000000000000 or
        #int(dsTimeStamp) >= 9223372036854775807 or
        int(dsTimeStamp) >= 2650467743999999999 or
        int(dsTimeStamp) == 0 or
        int(dsTimeStamp) == -1):
        return -1
    else:
        return int(dsTimeStamp)

def dsConvertToDSTimeStamp(dsTime):
    if dsVerifyDSTime(dsTime) != -1:
        return int(dsTime) * 10000000
    else:
        return -1
        
def dsGetDSDateTime(dsTimeStamp):
    if dsVerifyDSTimeStamp(dsTimeStamp) == -1:
        return "Never"
    else:
        return _FILETIME_null_date + datetime.timedelta(microseconds=int(dsTimeStamp) / 10)

def dsGetDSTimeStampStr(dsTimeStamp):
    if dsVerifyDSTimeStamp(dsTimeStamp) == -1:
        return "Never"
    else:
        return str(_FILETIME_null_date + datetime.timedelta(microseconds=int(dsTimeStamp) / 10))

def dsGetPOSIXTimeStamp(dsTimeStamp):
    ts = 0
    if  dsVerifyDSTimeStamp(dsTimeStamp) == -1:
        return 0
    else:
        try:
            ts = int(calendar.timegm(dsGetDSDateTime(dsTimeStamp).timetuple()))
        except ValueError:
            ts = int(calendar.timegm(dsGetDSDateTime(dsTimeStamp).timetuple()))
    return ts
    
# def dsGetPOSIXTimeStamp(dsTimeStamp):
#     ts = 0
#     if  dsVerifyDSTimeStamp(dsTimeStamp) == -1:
#         return 0
#     else:
#         try:
#             ts = int(calendar.timegm(time.strptime(dsGetDSTimeStampStr(dsTimeStamp), '%Y-%m-%d %H:%M:%S')))
#         except ValueError:
#             ts = int(calendar.timegm(time.strptime(dsGetDSTimeStampStr(dsTimeStamp), '%Y-%m-%d %H:%M:%S.%f')))
#     return ts

def dsGetDBLogTimeStampStr(dsDBLogTimeStamp):
    if len(dsDBLogTimeStamp) < 8:
        return ""
    (secs, mins, hours, days, months, years) = unpack('BBBBBBxx', dsDBLogTimeStamp)
    return (1900 + years, months, days, hours, mins, secs)

def dsGetDBTimeStampStr(dsDBTimeStamp):
    if len(dsDBTimeStamp) < 8:
        return ""
    (hours, mins, secs) = unpack('HHHxx', dsDBTimeStamp)
    return (hours, mins, secs)