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

import os
import sys

def normalizepath(path):
    return os.path.realpath(os.path.normpath(path))

def checkfile(path):
    if os.path.exists(normalizepath(path)) and os.path.isfile(normalizepath(path)):
        return True
    else:
        return False

def checkdir(path):
    if os.path.exists(normalizepath(path)):
        return True
    else:
        return False

def ensure_dir(path):
    if (not checkdir(path)) and (not os.path.isfile(normalizepath(path))):
        try:
            sys.stderr.write("\nThe directory (" + normalizepath(path) + ") specified does not exists!")
            sys.stderr.write("\nWould you like to create it? [Y/N] ")
            tmp = raw_input()
            #sys.stderr.write("\n%s" % tmp)
            if tmp.capitalize() == "Y":
                os.makedirs(normalizepath(path))
            else:
                raise Exception("The directory cannot be created")
        except:
            raise Exception("The directory cannot be created")
    return normalizepath(path)