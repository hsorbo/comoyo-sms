import socket
import json
import uuid
import thread
import threading
import time
import logging

class ComoyoWire():
    log = logging.getLogger("ComoyoWire")
    connected = False
    
    def connect(self):
        #TODO: Check if already connected ++
        self.log.debug("Connecting")
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.connect(('edgee-json.comoyo.com', 443))
        self._sslSocket = socket.ssl(self._socket)
        self.connected = True
        self.rxThread = threading.Thread(target=self._eventLoop,)
        self.rxThread.daemon = True
        self.rxThread.start()
        self.handle_connect()

    def disconnect(self):
        self.log.debug("Disconnecting")
        if not self.connected: return
        self.connected = False
        self._socket.close()
        self.handle_disconnect(True)

    def _eventLoop(self):
        read = ""
        while True:
            data = self._sslSocket.read(4096)
            if not data:
                if self.connected: self.handle_disconnect(False)
                self.connected = False
                self._socket.close()
                return
            read += data;
            if read[-1] == "\x00":
                for chunk in read.split("\x00"):
                    #use filter
                    if chunk == "": continue
                    self.log.debug("Receieved: %s" % chunk)
                    self.handle_recieved_entity(chunk)
                read = ""

    def handle_recieved_entity(self, data): pass
    def handle_connect(self): pass
    def handle_disconnect(self, expected): pass

    def write_entity(self, data = None):
        self.log.debug("Sending: %s" % data)
        if data: self._sslSocket.write(data)
        self._sslSocket.write("\x00")

class ComoyoTransport(ComoyoWire):
    def __init__(self, send_heartbeat = True): 
        self._send_heartbeat = send_heartbeat
        self.entity_subscribers = []
        self.connect_subscribers = []
        self.disconnect_subscribers = []
    
    def _init_heartbeat(self):
        if self._send_heartbeat and self.connected:
            t = threading.Thread(target=self._heartbeat)
            t.daemon = True
            t.start()

    def _heartbeat(self):
        #...   threading.Timer(10, foo).start() http://stackoverflow.com/questions/8600161/executing-periodic-actions-in-python
        #print "starting heartbeat"
        #http://stackoverflow.com/questions/2906510/correct-way-to-do-timer-function-in-python
        while True:
            time.sleep(50)
            if not self.connected:
                break
            self.write_entity(None)

    def handle_connect(self): 
        self._init_heartbeat()
        for s in self.connect_subscribers: s()

    def handle_disconnect(self, expected): 
        for s in self.disconnect_subscribers: s(expected)

    def handle_recieved_entity(self, data): 
        for s in self.entity_subscribers: s(json.loads(data))

    #TODO: take a lambda on "response-format" for special purpose mappers
    def send_command(self, command, response_format = None): 
        evt = threading.Event()
        r = {}
        def f(response):
            if response_format == None or response == None:
                r["response"] = None
                evt.set()
            elif response.has_key(response_format):
                r["response"] = response[response_format]
                evt.set()
            
        self.entity_subscribers.append(f)
        self.write_entity(json.dumps(command))
        evt.wait(10)
        self.entity_subscribers.remove(f)
        response = r["response"]
        return response

class ComoyoLogin():
    CLIENT_INFO =  { "clientInformation" : { 
        "imsi" : "Sms Windows Client",
        "imei" : "000000000000000000",
        "clientLocaleTag" : "en-US",
        "clientType" : "Sms Windows Client",
        "clientVersion" : "2012.1.320.0",
        "protocolVersion" : "1.13.26"
        }}

    def __init__(self, transport):
        self._transport = transport

    def activate(self): 
        activate_command = {"com.telenor.sw.adaptee.th.ClientActiveCommand" : self.CLIENT_INFO }
        response_key = "com.telenor.sw.footee.common.th.ClientActiveResponse"
        response = self._transport.send_command(activate_command, response_key)

    def authenticate(self, sessionKey, userId, clientId):
        auth_info = { "sessionKey" : sessionKey, "userId" : userId, "clientId" : clientId, "commandVersion" : 0 }
        auth_command = {
            "com.telenor.sw.adaptee.th.AuthenticateSessionCommand" : { 
                "authenticateSessionInformation" : auth_info }}
        response_key = "com.telenor.sw.footee.common.th.AuthenticateSessionResponse"
        response = self._transport.send_command(auth_command, response_key)

    def register(self):
        register_command = {"com.telenor.sw.adaptee.th.ClientRegistrationCommand" : self.CLIENT_INFO}
        response_key = "com.telenor.sw.footee.common.th.ClientRegistrationResponse"
        response = self._transport.send_command(register_command, response_key)
        return response["clientId"]

    def login(self, username, password, clientId):
        login_info = {"userName": username, "password": password,"clientId": clientId}
        login_command = {"com.telenor.sw.adaptee.th.AccountLoginCommand" : {"accountLoginInformation": login_info }}
        response_key = "com.telenor.sw.footee.common.th.AccountLoginResponse"
        response = self._transport.send_command(login_command, response_key)
        if not response["loggedIn"]: raise Exception("Login error, perhaps +47 ?")
        return response


class ComoyoSMS():
    def __init__(self, transport):
        self._transport= transport
        transport.entity_subscribers.append(self._on_event)
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
        response = self._transport.send_command(send_sms_command)


    def get_conversations(self, start, end):
        generationRange = {"generationRangeStart" : start, "generationRangeEnd": end }
        command = {
            "com.telenor.sw.adaptee.th.ConversationUpdateRequestCommand":
            {"generationRange": generationRange}
        }
        response = self._transport.send_command(command, "com.telenor.sw.adaptee.th.ConversationUpdateResponse")
        return response["conversations"]
    
    def enable_smsplus(self):
        """Dunno
        """
        command = {"com.telenor.sw.adaptee.th.ServiceRequestCommand":{"serviceId":"smsplus"}}
        self._transport.send_command(command, "com.telenor.sw.footee.common.th.ServiceResponse")

    def enable_subscription(self, subscribeToContactUpdates = True, subscribeToConversationUpdates = True):
        command = {
            "com.telenor.sw.adaptee.th.SubscriptionCommand":{
                "subscriptionInformation":{
                    "subscribeToContactUpdates": subscribeToContactUpdates,
                    "subscribeToConversationUpdates": subscribeToConversationUpdates
                }
            }
        }
        self._transport.send_command(command)   
    

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