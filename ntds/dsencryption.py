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

'''
Part of the code is based on creddump by Brendan Dolan-Gavitt

Many thanks to my colleague LASZLO TOTH (www.soonerorlater.hu)
for his help with researching the encryption algorithms
used by Microsoft ActiveDirectory
'''

from framework.addrspace import HiveFileAddressSpace
from framework.win32.hashdump import sid_to_key, get_bootkey
from Crypto.Hash import MD5
from Crypto.Cipher import ARC4,DES
from struct import unpack,pack
from binascii import *
import sys
import datetime

def get_syskey(syshive_fname):
    sysaddr = HiveFileAddressSpace(syshive_fname)
    bootkey = get_bootkey(sysaddr)
    return bootkey

def dsDecryptPEK(bootkey, enc_pek):
    md5=MD5.new()
    md5.update(bootkey)
    for i in range(1000):
        md5.update(enc_pek[0:16])
    rc4_key=md5.digest();
    rc4 = ARC4.new(rc4_key)
    pek=rc4.encrypt(enc_pek[16:])
    #return pek[36:]
    return pek[len(pek) - 16:]

def dsDecryptWithPEK(pek, enc_hash):
    md5=MD5.new()
    md5.update(pek)
    md5.update(enc_hash[0:16])
    rc4_key=md5.digest();
    rc4 = ARC4.new(rc4_key)
    return rc4.encrypt(enc_hash[16:])

def dsDecryptSingleHash(rid, enc_hash):
    (des_k1,des_k2) = sid_to_key(rid)
    d1 = DES.new(des_k1, DES.MODE_ECB)
    d2 = DES.new(des_k2, DES.MODE_ECB)
    hash = d1.decrypt(enc_hash[:8]) + d2.decrypt(enc_hash[8:])
    return hash