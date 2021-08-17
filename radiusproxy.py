#!/usr/bin/python
from __future__ import print_function
from pyrad import dictionary, packet, server
from pyrad.client import Client
import logging
import os 
import sys

logging.basicConfig( level="DEBUG",
                    format="%(asctime)s [%(levelname)-8s] %(message)s")

OKTA_RADIUS_AGENT_HOST = "192.168.0.107"
OKTA_RADIUS_AGENT_SECRET = b"Tecnics2021"
OKTA_RADIUS_AUTH_PORT = 1815


def initAuth(user_name):
    srv = Client(server=OKTA_RADIUS_AGENT_HOST, secret=OKTA_RADIUS_AGENT_SECRET, authport=OKTA_RADIUS_AUTH_PORT,dict=dictionary.Dictionary("dictionary"))
    req = srv.CreateAuthPacket(code=packet.AccessRequest, User_Name=user_name)
    # send push as a default secret for passwordless authentication
    req["User-Password"] = req.PwCrypt("push")
    reply = srv.SendPacket(req)
    print(reply.code)
    
    return reply
    
class FakeServer(server.Server):

    def HandleAuthPacket(self, pkt):
        print("Received an authentication request")
        print("Attributes: ")
        user_name = None
        for attr in pkt.keys():
            if attr == "User-Name":
                user_name = pkt[attr]
            print("%s: %s" % (attr, pkt[attr]))

        reply = self.CreateReplyPacket(pkt, **{
            "Service-Type": "Framed-User",
        })

        reply.code = packet.AccessAccept
        if not user_name:
            reply.code = packet.AccessReject
            self.SendReplyPacket(pkt.fd, reply)
            
        okta_reply = initAuth(user_name)
        if okta_reply.code == packet.AccessReject:
            reply.code = packet.AccessReject
        self.SendReplyPacket(pkt.fd, reply)

    def HandleAcctPacket(self, pkt):

        print("Received an accounting request")
        print("Attributes: ")
        for attr in pkt.keys():
            print("%s: %s" % (attr, pkt[attr]))

        reply = self.CreateReplyPacket(pkt)
        self.SendReplyPacket(pkt.fd, reply)

    def HandleCoaPacket(self, pkt):

        print("Received an coa request")
        print("Attributes: ")
        for attr in pkt.keys():
            print("%s: %s" % (attr, pkt[attr]))

        reply = self.CreateReplyPacket(pkt)
        self.SendReplyPacket(pkt.fd, reply)

    def HandleDisconnectPacket(self, pkt):

        print("Received an disconnect request")
        print("Attributes: ")
        for attr in pkt.keys():
            print("%s: %s" % (attr, pkt[attr]))

        reply = self.CreateReplyPacket(pkt)
        # COA NAK
        reply.code = 45
        self.SendReplyPacket(pkt.fd, reply)

if __name__ == '__main__':
    if not all(v in os.environ for v in ["OKTA_RADIUS_AGENT_HOST", "OKTA_RADIUS_AGENT_SECRET", "OKTA_RADIUS_AUTH_PORT"]):
        logging.error("Missing environment variables!")
        sys.exit("Missing environment variables!")
    # create server and read dictionary
    srv = FakeServer(dict=dictionary.Dictionary("dictionary"), coa_enabled=False)
    # add clients (address, secret, name)
    srv.hosts["0.0.0.0"] = server.RemoteHost("0.0.0.0", b"Kah3choteereethiejeimaeziecumi", "0.0.0.0")
    srv.BindToAddress("0.0.0.0")
    logging.debug("Starting ...")
    # start server
    srv.Run()
    
    # initAuth("murthy_avsn@tecnics.com")
