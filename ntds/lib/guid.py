# This file is part of ntdsdump.
#
# ntdsdump is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ntdsdump is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with ntdsdump.  If not, see <http://www.gnu.org/licenses/>.

'''
@author:        Csaba Barta
@license:       GNU General Public License 2.0 or later
@contact:       csaba.barta@gmail.com
'''
from struct import *
from binascii import *

class GUID:
    strGUID = ""
    binGUID = ""
    data1 = -1
    data2 = -1
    data3 = -1
    data4 = -1
    data5 = -1
    
    def __init__(self, strGUID):
        if strGUID == "":
            return None
        self.strGUID = strGUID
        self.binGUID = unhexlify(self.strGUID)
        (self.data1, self.data2, self.data3) = unpack('IHH',self.binGUID[:8])
        self.data4 = hexlify(self.binGUID[8:10])
        self.data5 = hexlify(self.binGUID[10:])

    def __str__(self):
        return "%08x-%04x-%04x-%s-%s" % (self.data1, self.data2, self.data3, self.data4, self.data5)    