#!/usr/bin/python3
from autobahn.asyncio.websocket import WebSocketClientProtocol, WebSocketClientFactory
from datetime import date
import asyncio
import json
import socket
import time

class MyClientProtocol(WebSocketClientProtocol):

    def onConnect(self, response):
        print("Server connected: {0}".format(response.peer))

    async def onOpen(self):
        print("WebSocket connection open.")

        try:
            res = await self.heartbeat()
        except Exception as e:
            self.sendClose(1000, "Exception raised: {0}".format(e))
        else:
            self.sendMessage(json.dumps(res).encode('utf-8'))

    def onMessage(self, payload, isBinary):
        if not isBinary:
            print("ATTENTION: Binary message received: {0} bytes -> DROPPED".format(len(payload)))
        else:
            msg = payload.strip()
            print("Message received: {}".format(msg))
            command = msg.split(b'::')
            #print(command)
            user = command[0]
            password = command[1]
            print("User: {}".format(str(user)))
            print("Passwort: {}".format(str(password)))
            #s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            #connect = s.connect(("192.168.165.5",110))
            #answer = s.recv(1024)
            #self.sendMessage(answer,1)
            #s.send(user + b'\r\n')
            #answer = s.recv(1024)
            #self.sendMessage(answer,1)
            #s.send(password + b'\r\n')
            #answer = s.recv(1024)
            #self.sendMessage(answer,1)
            #s.close()

    def onClose(self, wasClean, code, reason):
        print("WebSocket connection closed: {0}".format(reason))

    async def heartbeat(self):
        while True:
            await asyncio.sleep(29)
            msg = u"--- MARK ---"
            self.sendMessage(msg.encode('utf-8'))

if __name__ == '__main__':

    factory = WebSocketClientFactory(u"ws://192.168.165.20:80")
    factory.protocol = MyClientProtocol

    loop = asyncio.get_event_loop()
    coro = loop.create_connection(factory, '192.168.165.20', 80)
    loop.run_until_complete(coro)

    try:
        loop.run_forever()
    except KeyBoardInterrupt:
        pass
    finally:
        loop.close()

