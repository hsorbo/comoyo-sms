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
import time

SESSION_FILE = os.path.expanduser("~/.sendsms.json")

CLIENT_INFO =  { 
		"imsi" : "Sms Windows Client",
		"imei" : "000000000000000000",
		"clientLocaleTag" : "en-US",
		"clientType" : "Sms Windows Client",
		"clientVersion" : "2012.1.320.0",
		"protocolVersion" : "1.13.26"
		}

class ComoyoTransport():
	def __init__(self, sslSocket):
		self._sslSocket = sslSocket
		self._subscribers = []
		self._disconnect_handlers = []
		self.rxThread = threading.Thread(target=self._eventLoop,)
		self.rxThread.daemon = True
		self.rxThread.start()

	def _eventLoop(self):
		read = ""
		while True:
			data = self._sslSocket.read(4096)
			if not data: 
				for disconnect in self._disconnect_handlers:
					disconnect()
				break
			read += data;
			if read[-1] == "\x00":
				for chunk in read.split("\x00"):
					#use filter
					if chunk == "": continue
					for subscriber in self._subscribers:
						subscriber(json.loads(chunk))
				read = ""

	def register_handler(self, f):
		self._subscribers.append(f)
	
	def unregister_handler(self, f):
		self._subscribers.remove(f)

	def register_disconnect_handler(self, f):
		self._disconnect_handlers.append(f)

	def unregister_disconnect_handler(self, f):
		self._disconnect_handlers.append(f)

	def write(self, obj):
		#print "SEND:"
		#print json.dumps(obj, indent=1)
		self._sslSocket.write(json.dumps(obj))
		self.commit()
	
	def commit(self): self._sslSocket.write("\x00")


class ComoyoCommander():
	def __init__(self, transport):
		self._transport = transport

		#TODO: take a lambda on "response-format" for special purpose mappers
	def send_command(self, command, response_format = None): 
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
			
		self._transport.register_handler(f)
		self._transport.write(command)
		evt.wait(10)
		self._transport.unregister_handler(f)
		response = r["response"]
		return response

class ComoyoLogin():
	def __init__(self, commander):
		self._commander = commander

	def activate(self):	
		activate_command = {"com.telenor.sw.adaptee.th.ClientActiveCommand" : { "clientInformation" : CLIENT_INFO }}
		response = self._commander.send_command(activate_command, "com.telenor.sw.footee.common.th.ClientActiveResponse")

	def authenticate(self, auth_info):
		#destructive, fix
		auth_info["commandVersion"] = 0
		auth_command = {"com.telenor.sw.adaptee.th.AuthenticateSessionCommand" : { "authenticateSessionInformation" : auth_info }}
		response = self._commander.send_command(auth_command, "com.telenor.sw.footee.common.th.AuthenticateSessionResponse")

	def register(self):
		register_command = {"com.telenor.sw.adaptee.th.ClientRegistrationCommand" : { "clientInformation" : CLIENT_INFO}}
		response = self._commander.send_command(register_command)
		return response["com.telenor.sw.footee.common.th.ClientRegistrationResponse"]["clientId"]

	def login(self, username, password, clientId):
		login_info = {"userName": username, "password": password,"clientId": clientId}
		login_command = {"com.telenor.sw.adaptee.th.AccountLoginCommand" : {"accountLoginInformation": login_info }}
		response = self._commander.send_command(login_command)
		registration_response = response["com.telenor.sw.footee.common.th.AccountLoginResponse"]
		if not registration_response["loggedIn"]: raise Exception("Login error, perhaps +47 ?")
		registration_response["clientId"] = clientId
		return registration_response


class ComoyoSMS():
	def __init__(self, transport, commander):
		self._commander = commander
		transport.register_handler(self._on_event)
		self._conversation_latest = 0
		self._conversation_handlers = []
		self._delta_conversation_handlers = []
		self._conversations = []


	def send_sms(self, number, message):
		message = {
			"timestamp" : 0,
			"messageReceiver" : number,
			"smsContent" : message,
			"token": str(uuid.uuid1())
		}
		send_sms_command = {"com.telenor.sw.adaptee.th.SendSmsCommand" : { "smsMessage" : message }}
		response = self._commander.send_command(send_sms_command)


	def get_conversations(self, start, end):
		generationRange = {"generationRangeStart" : start, "generationRangeEnd": end }
		command = {
			"com.telenor.sw.adaptee.th.ConversationUpdateRequestCommand":
			{"generationRange": generationRange}
		}
		return self._commander.send_command(command, "com.telenor.sw.adaptee.th.ConversationUpdateResponse")["conversations"]
	
	def enable_smsplus(self):
		"""Dunno
		"""
		command = {"com.telenor.sw.adaptee.th.ServiceRequestCommand":{"serviceId":"smsplus"}}
		self._commander.send_command(command, "com.telenor.sw.footee.common.th.ServiceResponse")

	def enable_subscription(self, subscribeToContactUpdates = True, subscribeToConversationUpdates = True):
		command = {
			"com.telenor.sw.adaptee.th.SubscriptionCommand":{
				"subscriptionInformation":{
					"subscribeToContactUpdates": subscribeToContactUpdates,
					"subscribeToConversationUpdates": subscribeToConversationUpdates
				}
			}
		}
		self._commander.send_command(command)	
	

	def _on_event(self, event):
		if(event is not None and event.has_key("com.telenor.sw.adaptee.th.ConversationHgn")):
			gen = event["com.telenor.sw.adaptee.th.ConversationHgn"]["generation"]
			thread.start_new_thread(self._update_conversations, (self._conversation_latest, gen) )
			self._conversation_latest = gen

	def _update_conversations(self, minimum, maximum):
		new_conversations = self.get_conversations(minimum, maximum)
		self._conversations.extend(new_conversations)
		for conversation_handler in self._delta_conversation_handlers:
			conversation_handler(new_conversations)
		for conversation_handler in self._conversation_handlers:
			conversation_handler(self._conversations)

	def register_conversations_handler(self, f):
		self._conversation_handlers.append(f)

	def register_delta_conversations_handler(self, f):
		self._delta_conversation_handlers.append(f)


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
	import os
	def die(): 
		print "Disconnected"
		os._exit(0)
	transport.register_disconnect_handler(die)

def heartbeat(connection):
	def hb():
		while True:
			time.sleep(50)
			connection.commit()
	t = threading.Thread(target=hb)
	t.daemon = True
	t.start()
	return t

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Sends SMS via Telenor/Comoyo API')
	subparsers = parser.add_subparsers(title='subcommands', description='valid subcommands', help='additional help')
	send_parser = subparsers.add_parser('send', help='send number "message"')
	send_parser.add_argument('send',  nargs=2)

	login_parser = subparsers.add_parser('login', help='login username password')
	login_parser.add_argument('login',  nargs=2)

	monitor_parser = subparsers.add_parser('monitor', help='monitor')
	monitor_parser.add_argument('monitor', action="store_true")

	args = parser.parse_args()

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(('edgee-json.comoyo.com', 443))
	sslSocket = socket.ssl(s)
	transport = ComoyoTransport(sslSocket)
	commander = ComoyoCommander(transport)
	login = ComoyoLogin(commander)
	sms =  ComoyoSMS(transport, commander)
	login.activate()
		
	arg_dict = vars(args)
	if arg_dict.has_key("send"):
		settings = load_settings()
		login.authenticate(settings)
		sms.send_sms(arg_dict["send"][0], arg_dict["send"][1])

	elif arg_dict.has_key("login"):
		(username, password) = (arg_dict["login"][0], arg_dict["login"][1])
		settings = login.login(username, password, comoyo.register())
		save_settings(settings)

	elif args.monitor:
		settings = load_settings()
		login.authenticate(settings)
		monitor(transport, sms)
		hbThread = heartbeat(transport)
		transport.rxThread.join(2**31)
		hbThread.join(2**31)


	s.close()