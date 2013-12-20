import socket
import json
import uuid
import thread
import threading
import time
import logging

class ComoyoWire():
    log = logging.getLogger("ComoyoWire")

    def __init__(self, sslSocket):
        self._sslSocket = sslSocket

    def start(self):
        self.rxThread = threading.Thread(target=self._eventLoop,)
        self.rxThread.daemon = True
        self.rxThread.start()

    def _eventLoop(self):
        read = ""
        while True:
            data = self._sslSocket.read(4096)
            if not data: 
                self.handle_disconnect()
                break
            read += data;
            if read[-1] == "\x00":
                for chunk in read.split("\x00"):
                    #use filter
                    if chunk == "": continue
                    self.log.debug("Receieved: %s" % chunk)
                    self.handle_recieved_entity(chunk)
                read = ""

    def handle_recieved_entity(self, data): pass

    def handle_disconnect(self): pass

    def write_entity(self, data = None):
        self.log.debug("Sending: %s" % data)
        if data: self._sslSocket.write(data)
        self._sslSocket.write("\x00")

class ComoyoTransport(ComoyoWire):
    def __init__(self, sslSocket, send_heartbeat = True): 
        ComoyoWire.__init__(self, sslSocket)
        self._subscribers = []
        self._send_heartbeat = send_heartbeat

    def start(self):
        ComoyoWire.start(self)
        if self._send_heartbeat:
            t = threading.Thread(target=self._heartbeat)
            t.daemon = True
            t.start()

    def _heartbeat(self):
        while True:
            time.sleep(50)
            self.write_entity(None)

    def handle_recieved_entity(self, data):
        for subscriber in self._subscribers: subscriber(json.loads(data))

    def register_handler(self, f): self._subscribers.append(f)
    def unregister_handler(self, f): self._subscribers.remove(f)

        #TODO: take a lambda on "response-format" for special purpose mappers
    def send_command(self, command, response_format = None): 
        evt = threading.Event()
        r = {}
        def f(response):
            if response_format == None or response == None:
                r["response"] = None
            elif response.has_key(response_format):
                r["response"] = response[response_format]
            evt.set()
            
        self.register_handler(f)
        self.write_entity(json.dumps(command))
        evt.wait(10)
        self.unregister_handler(f)
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

    def authenticate(self, auth_info):
        #destructive, fix
        auth_info["commandVersion"] = 0
        auth_command = {
            "com.telenor.sw.adaptee.th.AuthenticateSessionCommand" : { 
                "authenticateSessionInformation" : auth_info }}
        response_key = "com.telenor.sw.footee.common.th.AuthenticateSessionResponse"
        response = self._transport.send_command(auth_command, response_key)

    def register(self):
        register_command = {"com.telenor.sw.adaptee.th.ClientRegistrationCommand" : self.CLIENT_INFO}
        response = self._transport.send_command(register_command)
        return response["com.telenor.sw.footee.common.th.ClientRegistrationResponse"]["clientId"]

    def login(self, username, password, clientId):
        login_info = {"userName": username, "password": password,"clientId": clientId}
        login_command = {"com.telenor.sw.adaptee.th.AccountLoginCommand" : {"accountLoginInformation": login_info }}
        response = self._transport.send_command(login_command)
        registration_response = response["com.telenor.sw.footee.common.th.AccountLoginResponse"]
        if not registration_response["loggedIn"]: raise Exception("Login error, perhaps +47 ?")
        registration_response["clientId"] = clientId
        return registration_response


class ComoyoSMS():
    def __init__(self, transport):
        self._transport= transport
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


def connect_comoyo():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('edgee-json.comoyo.com', 443))
    return (s,  socket.ssl(s))
