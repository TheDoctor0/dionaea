#!/usr/bin/env python3

from gemaltic.utils.api import is_api_available
from gemaltic.utils.api import api_request
from dionaea import IHandlerLoader
from dionaea.core import ihandler
import threading
import sched
import time


class GemalticLoggerHandlerLoader(IHandlerLoader):
    name = "gemaltic_logger"

    @classmethod
    def start(cls, config=None):
        del config

        cls.handler = GemalticLoggerHandler()

        return cls.handler


class GemalticLoggerHandler(ihandler):
    def __init__(self):
        ihandler.__init__(self, '*')

        self.connections = {}
        self.services = {}
        self.packets = {}
        self.scheduler = sched.scheduler(time.time, time.sleep)
        self.scheduler.enter(15, 15, self.send_data)

        threading.Thread(target=lambda: self.scheduler.run(), daemon=True).start()

    def send_data(self):
        if is_api_available():
            if len(self.packets):
                api_request('honeypot/packets', {'packets': self.__transform_dict(self.packets)})

                self.packets.clear()

            if len(self.services):
                api_request('honeypot/services', {'services': self.__transform_dict(self.services)})

                self.services.clear()

        self.scheduler.enter(15, 15, self.send_data)

    def handle_incident(self, incident):
        pass

    def _append_credentials(self, incident):
        connection = self.connections.get(incident.con)

        if not connection:
            return

        credentials = {
            "username": self._prepare_value(incident.username),
            "password": self._prepare_value(incident.password),
        }

        if credentials not in connection["credentials"]:
            connection["credentials"].append(credentials)

    @staticmethod
    def __transform_dict(dictionary):
        return [{**{'ip': key}, **value} for key, value in dictionary.items()]

    @staticmethod
    def _prepare_value(value):
        return value.decode(encoding="utf-8", errors="replace") if isinstance(value, bytes) else value

    def _serialize_connection(self, incident, connection_type):
        connection = incident.con

        if connection_type != 'reject':
            self.connections[connection] = {
                "protocol": connection.protocol,
                "port": connection.local.port,
                "hostname": self._prepare_value(connection.remote.hostname),
                "credentials": [],
                "count": 1
            }

        if connection.remote.host and connection.remote.host not in self.packets:
            self.packets[connection.remote.host] = {'count': 1}
        else:
            self.packets[connection.remote.host]['count'] += 1

    def handle_incident_dionaea_connection_tcp_listen(self, incident):
        self._serialize_connection(incident, "listen")

    def handle_incident_dionaea_connection_tls_listen(self, incident):
        self._serialize_connection(incident, "listen")

    def handle_incident_dionaea_connection_tcp_connect(self, incident):
        self._serialize_connection(incident, "connect")

    def handle_incident_dionaea_connection_tls_connect(self, incident):
        self._serialize_connection(incident, "connect")

    def handle_incident_dionaea_connection_udp_connect(self, incident):
        self._serialize_connection(incident, "connect")

    def handle_incident_dionaea_connection_tcp_accept(self, incident):
        self._serialize_connection(incident, "accept")

    def handle_incident_dionaea_connection_tls_accept(self, incident):
        self._serialize_connection(incident, "accept")

    def handle_incident_dionaea_connection_tcp_reject(self, incident):
        self._serialize_connection(incident, "reject")

    def handle_incident_dionaea_connection_free(self, incident):
        connection = incident.con

        if connection in self.connections:
            data = self.connections.get(connection)

            if data and connection.remote.host:
                if connection.remote.host not in self.services:
                    self.services[connection.remote.host] = data
                else:
                    self.services[connection.remote.host]['count'] += 1

                    for credentials in data['credentials']:
                        if credentials not in self.services[connection.remote.host]['credentials']:
                            self.services[connection.remote.host]['credentials'].append(credentials)

            del self.connections[connection]

    def handle_incident_dionaea_modules_python_ftp_login(self, incident):
        self._append_credentials(incident)

    def handle_incident_dionaea_modules_python_mssql_login(self, incident):
        self._append_credentials(incident)

    def handle_incident_dionaea_modules_python_mysql_login(self, incident):
        self._append_credentials(incident)
