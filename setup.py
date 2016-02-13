#!/usr/bin/python

import glob
import os

from distutils.core import setup

PACKAGE_NAME = "ntdsxtract"

setup(name = PACKAGE_NAME,
      version = "1.3.3.20150928",
      description = "Active Directory forensic framework",
      url = "http://www.ntdsxtract.com",
      author = "Csaba Barta",
      author_email = "csaba.barta@gmail.com",
      maintainer = "Csaba Barta",
      maintainer_email = "csaba.barta@gmail.com",
      license = "GPLv3",
      long_description = 'Active Directory forensic framework',
      platforms = ["Unix","Windows"],
      packages = ['framework', 'framework.win32', 'ntds', 'ntds.lib'],
      scripts = ['dscomputers.py', 'dsdeletedobjects.py', 'dsfileinformation.py', 'dsgroups.py', 'dskeytab.py', 'dstimeline.py', 'dsusers.py'],
      data_files = [(os.path.join('share', 'doc', PACKAGE_NAME), ['README.md', 'LICENSE', 'release_notes.txt'])],
      requires=['libesedb'],
      )

