#!/usr/bin/python
# -*- coding: utf-8 -*-
from cortexutils.analyzer import Analyzer

import json,mcafee,urlquote,sys
reload(sys)
sys.setdefaultencoding('utf-8')

class ePoAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param('config.service', None, 'Service parameter is missing')
        self.hostname = self.get_param('config.hostname', None, 'Missing hostname')
        self.port = self.get_param('config.port', None, 'Missing port')
        self.user = self.get_param('config.user', None, 'Missing username')
        self.password = self.get_param('config.password', None, 'Missing password')

    def checkip(self, data):
        client = mcafee.client(self.hostname, self.port, self.user, self.password)
        systems = client.system.find(data)
        for system in systems:
            ip = system['EPOComputerProperties.IPAddress']
            if ip == data:
                r = system
        return json.loads(json.dumps(r))
		
    def checkuser(self, data):
        client = mcafee.client(self.hostname, self.port, self.user, self.password)
        systems = client.system.find(data)
        for system in systems:
            username = system['EPOComputerProperties.UserName']
            if username == data:
                r = system
        return json.loads(json.dumps(r))

    def summary(self, raw):
        taxonomies = []
        level = "suspicious"
        namespace = "ePo"
        predicate = "host"
        value = "-"
        if self.data_type == 'ip':
            hostname = raw.get('EPOComputerProperties.ComputerName', [])
            username = raw.get('EPOComputerProperties.UserName', [])
            if 'EPOLeafNode.ManagedState' in raw.keys():
                level = "info"
                value = "{}/{}".format(hostname, username)
        elif self.data_type == 'other':
            hostname = raw.get('EPOComputerProperties.ComputerName', [])
            ipaddr = raw.get('EPOComputerProperties.IPAddress', [])
            if 'EPOLeafNode.ManagedState' in raw.keys():
                level = "info"
                value = "{}/{}".format(hostname, ipaddr)
        else:
            self.error('Invalid data type')
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}

    def artifacts(self, raw):
        artifacts = []
        if 'EPOComputerProperties.UserName' in raw.keys():
            artifacts.append({'type':'other','value':str(raw.get('EPOComputerProperties.UserName', []))})
        if 'EPOComputerProperties.IPHostName' in raw.keys():
            artifacts.append({'type': 'fqdn', 'value':str(raw.get('EPOComputerProperties.IPHostName', []))})
        if 'EPOComputerProperties.IPAddress' in raw.keys():
            artifacts.append({'type': 'ip', 'value':str(raw.get('EPOComputerProperties.IPAddress', []))})
        if 'EPOComputerProperties.ComputerName' in raw.keys():
            artifacts.append({'type': 'other', 'value':str(raw.get('EPOComputerProperties.ComputerName', []))})
        if 'EPOComputerProperties.NetAddress' in raw.keys():
            artifacts.append({'type': 'other', 'value':str(raw.get('EPOComputerProperties.NetAddress', []))})
        return artifacts
		
    def run(self):
        try:
            if self.data_type == 'ip':
                data = self.get_param('data', None, 'Data is missing')
                rep = self.checkip(data)
                self.report(rep)
            elif self.data_type == 'other':
                data = self.get_param('data', None, 'Data is missing')
                rep = self.checkuser(data)
                self.report(rep)
            else:
                self.error('Invalid data type')
        except:
            self.report({
                'message': '{} not found in McAfee ePo'.format(self.get_data())
            })

if __name__ == '__main__':
    ePoAnalyzer().run()
