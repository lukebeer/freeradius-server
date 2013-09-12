#! /usr/bin/env python
#
# Radius Python module for Broadworks authentication

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA

# Copyright 2013 Luke Beer <eat.lemons@gmail.com>
#
# $Id$

#
#   WARNING: THIS MODULE RAISES MORE QUESTIONS THAN ANSWERS.
#

import radiusd
from OCIControl import Client


hostname = ''
username = ''
password = ''
client = None


def log(level, s):
    radiusd.radlog(level, __file__[:-3] + ": %s" % s)


def instantiate():
    global client
    client = Client(url=hostname, username=username, password=password)
    try:
        client.login()
    except Exception as e:
        log(radiusd.L_ERR, str(e))


def authorize():
    pass


def authenticate(authData):
    if authData.type == 'AccessDeviceMACAddress':
        pass
    if authData.type == 'AccessDeviceName':
        pass
    if authData.type == 'UserId':
        pass


def preacct():
    return radiusd.RLM_MODULE_OK


def accounting(acctData):
    # Details returned from Broadworks to stamp in accounting log
    pass


def detach():
    global client
    log(radiusd.L_DBG, 'Closing OCI-P connection.')
    client.logout()
    return radiusd.RLM_MODULE_OK


if __name__ == '__main__':
    pass