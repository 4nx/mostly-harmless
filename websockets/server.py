#!/usr/bin/python3
from autobahn.asyncio.websocket import WebSocketServerProtocol, WebSocketServerFactory
import asyncio
import datetime
import json
import time

class MyServerProtocol(WebSocketServerProtocol):
    def onConnect(self, request):
        print("Client connecting: {}".format(request.peer))

    async def onOpen(self):
        print("WebSocket connection open.")

        try:
            res = await self.followFile()
        except Exception as e:
            self.sendClose(1000, "Exception raised: {0}".format(e))
        else:
            self.sendMessage(json.dumps(res).encode('utf-8'))

    def onMessage(self, payload, isBinary):
        now = datetime.datetime.now()

        #if isBinary:
        #   print("Binary message received: {0} bytes".format(len(payload)))
        #else:
        print("{0:%Y-%m-%d %H:%M:%S} Text message received: {1}".format(datetime.datetime.now(), payload.decode('utf-8')))

    def onClose(self, wasClean, code, reason):
        print("WebSocket connection closed: {0}".format(reason))

    async def followFile(self):
        with open('data.txt', 'r') as input_data:
            while True:
                time.sleep(2)
                line = input_data.readline()
                if not line:
                    #time.sleep(1)
                    await asyncio.sleep(1)
                    continue
                msg = line.encode('utf-8')
                self.sendMessage(msg,1)

if __name__ == '__main__':

    factory = WebSocketServerFactory(u"ws://127.0.0.1:9000")
    factory.protocol = MyServerProtocol

    loop = asyncio.get_event_loop()
    coro = loop.create_server(factory, '127.0.0.1', 9000)
    server = loop.run_until_complete(coro)

    try:
        loop.run_forever()
    except KeyBoardInterrupt:
        pass
    finally:
        server.close()
        loop.close()
