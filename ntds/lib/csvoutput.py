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

import csv

cw = None
cf = None

def init_csv(file):
    global cf, cw
    cf = open(file, "w")
    cw = csv.writer(cf, delimiter=";", quoting=csv.QUOTE_ALL)
    
def write_csv(record):
    global cw
    cw.writerow(record)

def close_csv():
    global cf
    cf.flush()
    cf.close()
    