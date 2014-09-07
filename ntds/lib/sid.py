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

class SID:
    '''
    classdocs
    '''
    Revision = -1
    SecurityAuthority = -1
    NumIDS = 0
    IDs    = []
    RID    = 0

    def __init__(self, strSID):
        '''
        Constructor
        '''
        if strSID == "":
            return None
        (self.Revision, ) = unpack('B', unhexlify(strSID[:2]))
        (self.SecurityAuthority, ) = unpack('>I', unhexlify(strSID[8:16]))
        self.NumIDS = (len(strSID) / 8) - 2
        (self.RID, ) = unpack('>I',unhexlify(strSID[len(strSID) - 8:]))
        
        self.IDs = []
        for id in range(0, self.NumIDS - 1):
            (tmp,) = unpack('I', unhexlify(strSID[(id + 2) * 8:(id + 2) * 8 + 8]))
            self.IDs.append(tmp)
        
    def __str__(self):
        strSID = "S-%d-%d" % (self.Revision, self.SecurityAuthority)
    
        for id in range(0, self.NumIDS-1):
            strSID += '-' + str(self.IDs[id])
        
        strSID += '-' + str(self.RID)
        
        return strSID
    