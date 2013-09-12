#! /usr/bin/env python
#
# Python OCI-P Client for Broadsoft Broadworks
# v0.1 shitty draft

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

import cgi
import hashlib
import HTMLParser
import httplib2
import random
import re


class OCISchemaDataTypes:

    def AccessDeviceMACAddress(self, value):
        return value

    def AccessDeviceName(self, value):
        return value


class OCISchemaSearchCriteria:

    def SearchCriteriaDeviceName(self, mode, value, isCaseInsensitive):
        return {
            'SearchCriteriaDeviceName': '',
            'Elements': {
                'mode': mode,
                'value': value,
                'isCaseInsensitive': isCaseInsensitive
            }
        }

    def SearchCriteriaDeviceMACAddress(self, mode, value, isCaseInsensitive):
        return {
            'SearchCriteriaDeviceMACAddress': '',
            'Elements': {
                'mode': mode,
                'value': value,
                'isCaseInsensitive': isCaseInsensitive
            }
        }


class OCISchemaSystem:

    def SystemAccessDeviceGetAllRequest(self, responseSizeLimit, searchCriteriaDeviceName,
                                        searchCriteriaDeviceMACAddress, searchCriteriaDeviceNetAddress,
                                        searchCriteriaGroupId, searchCriteriaExactDeviceType,
                                        searchCriteriaExactDeviceServiceProvider):
        return {
            'Name': 'SystemAccessDeviceGetAllRequest',
            'Elements': {
                'responseSizeLimit': responseSizeLimit,
                'searchCriteriaDeviceName': searchCriteriaDeviceName,
                'searchCriteriaDeviceMACAddress': searchCriteriaDeviceMACAddress,
                'searchCriteriaDeviceNetAddress': searchCriteriaDeviceNetAddress,
                'searchCriteriaGroupId': searchCriteriaGroupId,
                'searchCriteriaExactDeviceType': searchCriteriaExactDeviceType,
                'searchCriteriaExactDeviceServiceProvider': searchCriteriaExactDeviceServiceProvider
            }
        }


class OCISchemaLogin:

    def AuthenticationRequest(self, userId):
        return {
            'Name': 'AuthenticationRequest',
            'Elements': {
                'userId': userId
            }
        }

    def LoginRequest14sp4(self, userId, signedPassword):
        return {
            'Name': 'LoginRequest14sp4',
            'Elements': {
                'userId': userId,
                'signedPassword': signedPassword
            }
        }


class OCIBuilder:

    _oci = None
    params = None
    session_id = None

    def _get_soap_head(self):
        return """<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" >
    <soapenv:Body>
        <processOCIMessage soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
            <arg0 xsi:type="soapenc:string" xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
"""

    def _get_soap_tail(self):
        return """
            </arg0>
        </processOCIMessage>
    </soapenv:Body>
</soapenv:Envelope>"""

    def _build_oci(self):
        xml = '<BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        xml += '<sessionId xmlns="">%s</sessionId>' % self.session_id
        xml += '<command xsi:type="%s" xmlns="">' % self.params['Name']
        for key, value in self.params['Elements'].iteritems():
            xml += '<%s>%s</%s>' % (key, value, key)
        xml += '</command>'
        xml += '</BroadsoftDocument>'
        return cgi.escape(xml, quote=False)

    def build(self, params, session_id):
        self.params = params
        self.session_id = session_id
        return self._get_soap_head() + self._build_oci() + self._get_soap_tail()


class Client(OCIBuilder):

    _username = None
    _password = None
    _session_id = None
    _nonce = None
    _cookie = None
    _timeout = 2
    _url = None
    _request = None
    _response = None
    _request_body = None
    _response_body = None
    enterprise_id = None
    service_provider = None
    group_id = None
    user_id = None
    error_msg = None

    def __init__(self, url, username, password):
        self._url = url
        self._username = username
        self._password = password
        self._set_session_id()

    def _set_session_id(self):
        self._session_id = abs(random.randrange(0,1000000000000000000))

    def _get_session_id(self):
        if self._session_id is None:
            self._set_session_id()
        return self._session_id

    def _validate(self):
        body = self.decode_body(self._response_body)
        nonce = re.search("<nonce>(.*?)</nonce>", body)
        if nonce:
            self._nonce = nonce.group(1)
            return True
        error = re.search("<summaryEnglish>(.*?)</summaryEnglish>", body)
        if error:
            self.error_msg = error.group(1)
            return False

        return False

    def get_error(self):
        return self.error_msg

    def _get_headers(self):
        headers = {
            'Content-Type': 'text/xml; charset=utf-8',
            'Accept': 'application/soap+xml, application/dime, multipart/related, text/*',
            'User-Agent': 'Axis/1.3',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'SOAPAction': '',
            'Connection': '',
            'Accept-Encoding': '',
        }
        if self._response and self._response['set-cookie']:
            headers['Cookie'] = self._response['set-cookie']
        return headers

    def _submit_request(self):
        if self._request_body:
            encoded_body = self._request_body.replace("\n", "")
            http_agent = httplib2.Http(cache=None, timeout=self._timeout, disable_ssl_certificate_validation=True)
            self._response, self._response_body = \
                http_agent.request(self._url, method="POST", body=encoded_body, headers=self._get_headers())

    def authenticate(self):
        self._request_body = OCIBuilder().build(OCISchemaLogin().AuthenticationRequest(self._username), self._session_id)
        self._submit_request()
        if self._response.status == 200:
            return self._validate()
        return False

    def login(self):
        if self.authenticate():
            pw = hashlib.sha1()
            pw.update(self._nonce)
            sha1pw = pw.hexdigest()
            spw = hashlib.md5()
            spw.update("%s:%s" % (self._nonce, sha1pw))
            self._request_body = OCIBuilder().build(OCISchemaLogin().LoginRequest14sp4(self._username, spw.hexdigest()), self._session_id)
            self._submit_request()
            if self._response.status == 200:
                body = self.decode_body(self._response_body)
                return True
            raise Exception("%s: %s" % self._response.status)

    def decode_body(self, body):
        return HTMLParser.HTMLParser().unescape(body)

    def logout(self):
        pass