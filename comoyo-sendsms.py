#!/usr/bin/python

"""comoyo-sendsms.py: Sends SMS via Telenor/Comoyo."""

__author__      = "Havard Sorbo"
__copyright__   = "Copyright 2013"
__license__     = "GPL2"

import socket
import os
import argparse
import threading
import logging
from comoyo import *

SESSION_FILE = os.path.expanduser("~/.sendsms.json")

def load_settings():
    f = open(SESSION_FILE, 'r')
    settings = json.loads(f.read())
    f.close()
    return settings

def save_settings(settings):
    f = open(SESSION_FILE, 'w+')
    f.write(json.dumps(settings))
    f.close()


def monitor(transport, sms):
    sms.enable_smsplus()
    sms.enable_subscription()
    def conv_update(conversations):
        for conversation in conversations:
            message = conversation["latestMessage"]
            if not message["viewed"] and message.has_key("messageSender"):
                print message["messageSender"] 
                print message["body"]["richTextElements"][0]["richTextString"]["text"]
    sms.register_delta_conversations_handler(conv_update)



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Sends SMS via Telenor/Comoyo API')
    parser.add_argument('--debug', action = 'store_true')
    subparsers = parser.add_subparsers(title='subcommands', description='valid subcommands', help='additional help')
    send_parser = subparsers.add_parser('send', help='send number "message"')
    send_parser.add_argument('send',  nargs=2)

    login_parser = subparsers.add_parser('login', help='login username password')
    login_parser.add_argument('login',  nargs=2)

    monitor_parser = subparsers.add_parser('monitor', help='monitor')
    monitor_parser.add_argument('monitor', action="store_true")

    args = parser.parse_args()
    if(args.debug): logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.DEBUG)

    transport = ComoyoTransport()
    login = ComoyoLogin(transport)
    sms =  ComoyoSMS(transport)
    transport.connect()
    login.activate()
        
    arg_dict = vars(args)
    if arg_dict.has_key("send"):
        settings = load_settings()
        login.authenticate(settings["sessionKey"], settings["userId"], settings["clientId"])
        sms.send_sms(arg_dict["send"][0], arg_dict["send"][1])

    elif arg_dict.has_key("login"):
        (username, password) = (arg_dict["login"][0], arg_dict["login"][1])
        settings = login.login(username, password, login.register())
        save_settings(settings)

    elif args.monitor:
        settings = load_settings()
        login.authenticate(settings["sessionKey"], settings["userId"], settings["clientId"])
        monitor(transport, sms)
        transport.rxThread.join(2**31)
    transport.disconnect()