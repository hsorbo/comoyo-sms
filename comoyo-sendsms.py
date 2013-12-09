#!/usr/bin/python

"""comoyo-sendsms.py: Sends SMS via Telenor/Comoyo."""

__author__      = "Havard Sorbo"
__copyright__   = "Copyright 2013"
__license__ 	= "GPL2"

import socket
import json
import uuid
import os
import argparse
import thread
import threading

SESSION_FILE = os.path.expanduser("~/.sendsms.json")

CLIENT_INFO =  { 
		"imsi" : "Sms Windows Client",
		"imei" : "000000000000000000",
		"clientLocaleTag" : "en-US",
		"clientType" : "Sms Windows Client",
		"clientVersion" : "2012.1.320.0",
		"protocolVersion" : "1.13.26"
		}

class ComoyoSMS():
	def __init__(self, sslSocket):
		self._sslSocket = sslSocket
		self._subscribers = []
		def debug(x): 
			print "RECIEVE:"
			print(json.dumps(x, indent=1))
		self._subscribers.append(debug)
		thread.start_new_thread(self._eventLoop, () )

	def _eventLoop(self):
		read = ""
		while True:
			data = self._sslSocket.read(1024)
			#print data
			if not data: 
				print("disconnect")
				for subscriber in self._subscribers:
						subscriber(None)
				break
			
			read += data;

			if read[-1] == "\x00":
				for chunk in read.split("\x00"):
					#use filter
					if chunk == "": continue
					for subscriber in self._subscribers:
						subscriber(json.loads(chunk))
				read = ""

	def _send_command(self, command, response_format = None):
		evt = threading.Event()
		chunks = []
		r = {}
		def f(response):
			if response_format == None or response == None:
				r["response"] = None
				evt.set()
			elif response.has_key(response_format):
				r["response"] = response[response_format]
				evt.set()
			
	
		self._subscribers.append(f)
		print "SEND:"
		print json.dumps(command, indent=1)
		self._sslSocket.write(json.dumps(command) + "\x00")
		#sem.acquire()
		evt.wait(3)
		self._subscribers.remove(f)
		response = r["response"]
		return response

	def activate(self):	
		activate_command = {"com.telenor.sw.adaptee.th.ClientActiveCommand" : { "clientInformation" : CLIENT_INFO }}
		response = self._send_command(activate_command, "com.telenor.sw.footee.common.th.ClientActiveResponse")

	def authenticate(self, auth_info):
		#destructive, fix
		auth_info["commandVersion"] = 0
		auth_command = {"com.telenor.sw.adaptee.th.AuthenticateSessionCommand" : { "authenticateSessionInformation" : auth_info }}
		response = self._send_command(auth_command, "com.telenor.sw.footee.common.th.AuthenticateSessionResponse")

	def send_sms(self, number, message):
		message = {
			"timestamp" : 0,
			"messageReceiver" : number,
			"smsContent" : message,
			"token": str(uuid.uuid1())
		}
		send_sms_command = {"com.telenor.sw.adaptee.th.SendSmsCommand" : { "smsMessage" : message }}
		response = self._send_command(send_sms_command)

	def register(self):
		register_command = {"com.telenor.sw.adaptee.th.ClientRegistrationCommand" : { "clientInformation" : CLIENT_INFO}}
		response = self._send_command(register_command)
		return response["com.telenor.sw.footee.common.th.ClientRegistrationResponse"]["clientId"]

	def login(self, username, password, clientId):
		login_info = {"userName": username, "password": password,"clientId": clientId}
		login_command = {"com.telenor.sw.adaptee.th.AccountLoginCommand" : {"accountLoginInformation": login_info }}
		response = self._send_command(login_command)
		registration_response = response["com.telenor.sw.footee.common.th.AccountLoginResponse"]
		if not registration_response["loggedIn"]: raise Exception("Login error, perhaps +47 ?")
		registration_response["clientId"] = clientId
		return registration_response

	def get_conversations(self):
		generationRange = {"generationRangeStart" : 1, "generationRangeEnd": 999999999999999999999999999999999999 }
		command = {
			"com.telenor.sw.adaptee.th.ConversationUpdateRequestCommand":
			{"generationRange": generationRange}
		}
		return self._send_command(command, "com.telenor.sw.adaptee.th.ConversationUpdateResponse")
	
	def enable_smsplus(self):
		"""Dunno
		"""
		command = {"com.telenor.sw.adaptee.th.ServiceRequestCommand":{"serviceId":"smsplus"}}
		self._send_command(command, "com.telenor.sw.footee.common.th.ServiceResponse")

	def enable_subscription(self, subscribeToContactUpdates = True, subscribeToConversationUpdates = True):
		command = {
			"com.telenor.sw.adaptee.th.SubscriptionCommand":{
				"subscriptionInformation":{
					"subscribeToContactUpdates": subscribeToContactUpdates,
					"subscribeToConversationUpdates": subscribeToConversationUpdates
				}
			}
		}
		self._send_command(command)	

def load_settings():
	f = open(SESSION_FILE, 'r')
	settings = json.loads(f.read())
	f.close()
	return settings

def save_settings(settings):
	f = open(SESSION_FILE, 'w+')
	f.write(json.dumps(settings))
	f.close()


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Sends SMS via Telenor/Comoyo API')
	subparsers = parser.add_subparsers(title='subcommands', description='valid subcommands', help='additional help')
	send_parser = subparsers.add_parser('send', help='send number "message"')
	send_parser.add_argument('send',  nargs=2)

	login_parser = subparsers.add_parser('login', help='login username password')
	login_parser.add_argument('login',  nargs=2)

	args = parser.parse_args()

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(('edgee-json.comoyo.com', 443))
	sslSocket = socket.ssl(s)
	comoyo =  ComoyoSMS(sslSocket)

	arg_dict = vars(args)
	if arg_dict.has_key("send"):
		settings = load_settings()
		comoyo.activate()
		comoyo.authenticate(settings)
		comoyo.send_sms(arg_dict["send"][0], arg_dict["send"][1])

	elif arg_dict.has_key("login"):
		(username, password) = (arg_dict["login"][0], arg_dict["login"][1])
		comoyo.activate()
		settings = comoyo.login(username, password, comoyo.register())
		save_settings(settings)

	s.close()