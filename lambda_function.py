# -*- coding: utf-8 -*-

# This sample demonstrates handling intents from an Alexa skill using the Alexa Skills Kit SDK for Python.
# Please visit https://alexa.design/cookbook for additional examples on implementing slots, dialog management,
# session persistence, api calls, and more.
# This sample is built using the handler classes approach in skill builder.
import logging
import ask_sdk_core.utils as ask_utils

import os
import boto3

import time

from ask_sdk_core.api_client import DefaultApiClient
from ask_sdk_core.skill_builder import CustomSkillBuilder
from ask_sdk_dynamodb.adapter import DynamoDbAdapter

from ask_sdk_core.dispatch_components import AbstractRequestHandler
from ask_sdk_core.dispatch_components import AbstractExceptionHandler
from ask_sdk_core.handler_input import HandlerInput

from ask_sdk_model.interfaces.connections import SendRequestDirective
from ask_sdk_model.ui import AskForPermissionsConsentCard
from ask_sdk_core.dispatch_components import AbstractRequestInterceptor
from ask_sdk_core.dispatch_components import AbstractResponseInterceptor

from ask_sdk_model import Response

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


ddb_region = os.environ.get('DYNAMODB_PERSISTENCE_REGION')
ddb_table_name = os.environ.get('DYNAMODB_PERSISTENCE_TABLE_NAME')

ddb_resource = boto3.resource('dynamodb', region_name=ddb_region)
dynamodb_adapter = DynamoDbAdapter(table_name=ddb_table_name, create_table=False, dynamodb_resource=ddb_resource)

# Adam was here
#Dylan was here
# new_timer_request = {
#     "duration": "PT{}M".format(interval_length),
#     "timerLabel": "study",
#     "creationBehavior": {
#         "displayExperience": {
#             "visibility": "VISIBLE"
#         }
#     },
#     "triggeringBehavior": {
#         "operation": {
#             "type": "ANNOUNCE",
#             "textToAnnounce": [
#                 {
#                     "locale": "en-US",
#                     "text": "Let's take a break!"
#                 }
#             ]
#         },
#         "notificationConfig": {
#             "playAudible": True
#         }
#     }
# }

def getTimerRequest(interval_length):
    return {
        "duration": "PT{}M".format(interval_length),
        "timerLabel": "study",
        "creationBehavior": {
            "displayExperience": {
                "visibility": "VISIBLE"
            }
        },
        "triggeringBehavior": {
            "operation": {
                "type": "ANNOUNCE",
                "textToAnnounce": [
                    {
                        "locale": "en-US",
                        "text": "Let's take a break!"
                    }
                ]
            },
            "notificationConfig": {
                "playAudible": True
            }
        }
    }

REQUIRED_PERMISSIONS = ["alexa::alerts:timers:skill:readwrite"]


def get_uuid():
    return str(uuid.uuid4())


class LaunchRequestHandler(AbstractRequestHandler):
    """Handler for Skill Launch."""

    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool

        return ask_utils.is_request_type("LaunchRequest")(handler_input)

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response
        
        attr = handler_input.attributes_manager.persistent_attributes
        if not attr:
            attr['TimeStamp'] = 0
            attr['IntervalLength'] = 25
            
        handler_input.attributes_manager.session_attributes = attr

        handler_input.attributes_manager.save_persistent_attributes()

        speak_output = ("Hello! Welcome to Stay Focused. To learn more say Help. Otherwise, say start when ever you're ready to begin an interval.")

        reprompt = "Say Start or Help"
        return (
            handler_input.response_builder
                .speak(speak_output)
                .ask(reprompt)
                .response
        )


class TimerIntentHandler(AbstractRequestHandler):
    # only can be called if there if timer hasn't been paused
    def can_handle(self, handler_input):
        return ask_utils.is_request_type("IntentRequest")(handler_input) and (
                    ask_utils.is_intent_name("Start")(handler_input) or ask_utils.is_intent_name("AMAZON.YesIntent")(
                handler_input))

    def handle(self, handler_input):
        logger.info("In TimerIntent Handler")

        response_builder = handler_input.response_builder
        permissions = handler_input.request_envelope.context.system.user.permissions
        if not (permissions and permissions.consent_token):
            return response_builder.add_directive(
                SendRequestDirective(
                    name="AskFor",
                    payload={
                        "@type": "AskForPermissionsConsentRequest",
                        "@version": "1",
                        "permissionScope": "alexa::alerts:timers:skill:readwrite"
                    },
                    token="correlationToken"
                )
            ).response
        logger.info("Voice permission provided")
        
        timer_service = handler_input.service_client_factory.get_timer_management_service()
        timer_response = timer_service.create_timer(new_timer_request)
        logger.info("Timer created")

        if str(timer_response.status) == "Status.ON":
            session_attr = handler_input.attributes_manager.session_attributes
            if not session_attr:
                session_attr['lastTimerId'] = timer_response.id

            speech_text = 'Time to start studying.'
        else:
            speech_text = 'Timer did not start'

        return (
            handler_input.response_builder
                .speak(speech_text)
                .response
        )


class AcceptGrantResponseHandler(AbstractRequestHandler):
    def can_handle(self, handler_input):
        return ask_utils.is_request_type("Alexa.Authorization.Grant")(handler_input)

    def handle(self, handler_input):
        Get_Accept_Grant_Response = {
            "event": {
                "header": {
                    "namespace": "Alexa.Authorization",
                    "name": "AcceptGrant.Response",
                    "messageId": get_uuid(),
                    "payloadVersion": "3"
                },
                "payload": {}
            }
        }
        print("AcceptGrant Response: ", json.dumps(Get_Accept_Grant_Response))
        return json.loads(json.dumps(Get_Accept_Grant_Response))


class ConnectionsResponsehandler(AbstractRequestHandler):
    def can_handle(self, handler_input):
        return ((ask_utils.is_request_type("Connections.Response")(handler_input) and \
                 handler_input.request_envelope.request.name == "AskFor"))

    def handle(self, handler_input):
        logger.info("In Connections Response Handler")

        response_payload = handler_input.request_envelope.request.payload
        response_status = response_payload['status']

        if (response_status == 'NOT_ANSWERED'):
            return handler_input.response_builder.speak(
                "Please provide timer permissions using card I have sent to your Alexa app.").set_card(
                AskForPermissionsConsentCard(permissions=REQUIRED_PERMISSIONS)).response

        elif (response_status == 'DENIED'):
            return handler_input.response_builder.speak(
                "You can grant permission anytime by going to Alexa app.").response

        else:
            return handler_input.response_builder.speak("Please say set timer").ask("Please say set timer").response


class SessionResumedHandlerRequest(AbstractRequestHandler):
    def can_handle(self, handler_input):
        return ask_utils.is_request_type("SessionResumedRequest")(handler_input)

    def handle(self, handler_input):
        response_builder = handler_input.response_builder
        status = handler_input.request_envelope.request.cause.status
        result = handler_input.request_envelope.request.cause.result
        code = status.code
        message = status.message
        speechText = "Got back ! Status code is {}, message is {}".format(code, message)
        if (code == '200'):
            speechText = "Got back ! Status code is {}, message is {} and payload is {}".format(code, message,
                                                                                                result.payload)

        response_builder.speak(speechText)
        return response_builder.response


class PomodoroIntentHandler(AbstractRequestHandler):
    """Handler for Pomodoro Intent."""

    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return ask_utils.is_intent_name("PomodoroIntent")(handler_input)

    def handle(self, handler_input):
        
        attr = handler_input.attributes_manager.persistent_attributes
        speak_output = "error: something went wrong while building your timer."
        
        if(time.time() > attr["TimeStamp"]):
            #update timer
            session_attr = handler_input.attributes_manager.session_attributes
            session_attr['TimeStamp'] = int(time.time()) + (session_attr['IntervalLength'] * 60)
            handler_input.attributes_manager.persistent_attributes = session_attr
            handler_input.attributes_manager.save_persistent_attributes()
            timer_service = handler_input.service_client_factory.get_timer_management_service()
            timer_request = getTimerRequest(session_attr['IntervalLength'])
            timer_response = timer_service.create_timer(timer_request)
            speak_output = "Your interval has started. Please put away all distractions and begin you're work. I'll let you know when its time for a break."
        
        else:
            speak_output = "You already have a timer interval started. you have "+ str(int((attr["TimeStamp"] - int(time.time())) / 60)) +" minutes left."

        return (
            handler_input.response_builder
                .speak(speak_output)
                #.ask("Let me know if you finish early by saying done or want to pause your interval.")
                .response
        )


class CustomIntervalIntentHandler(AbstractRequestHandler):
    def can_handle(self, handler_input):
        return ask_utils.is_intent_name("CustomIntervalIntent")(handler_input)

    def handle(self, handler_input):
        slots = handler_input.request_envelope.request.intent.slots
        interval_minutes = slots["Interval"].value

        attr = handler_input.attributes_manager.persistent_attributes
        speak_output = "error: something went wrong while building your timer."
        if(time.time() > attr["TimeStamp"]):
            session_attr = handler_input.attributes_manager.session_attributes
            session_attr['IntervalLength'] = int(interval_minutes)
            session_attr['TimeStamp'] = int(time.time()) + (int(interval_minutes) * 60)
            handler_input.attributes_manager.persistent_attributes = session_attr
            handler_input.attributes_manager.save_persistent_attributes()
            timer_service = handler_input.service_client_factory.get_timer_management_service()
            timer_request = getTimerRequest(session_attr['IntervalLength'])
            timer_response = timer_service.create_timer(timer_request)
            speak_output = "Your " + str(interval_minutes) + " minute interval has started."
            
        else:
            speak_output = "You already have a timer interval started. you have "+ str(int((attr["TimeStamp"] - int(time.time())) / 60)) +" minutes left."



        return (
            handler_input.response_builder
                .speak(speak_output)
                .ask(speak_output)
                .response
        )


class PauseIntentHandler(AbstractRequestHandler):
    def can_handle(self, handler_input):
        return ask_utils.is_intent_name("PauseIntent")(handler_input)

    def handle(self, handler_input):
        speak_output = "Your interval is paused"
        return (
            handler_input.response_builder
                .speak(speak_output)
                .ask("pause")
                .response
        )


class ResumeIntentHandler(AbstractRequestHandler):
    def can_handle(self, handler_input):
        return ask_utils.is_intent_name("ResumeIntent")(handler_input)

    def handle(self, handler_input):
        speak_output = "Resuming interval!"
        return (
            handler_input.response_builder
                .speak(speak_output)
                .ask("resume")
                .response
        )


class HelpIntentHandler(AbstractRequestHandler):
    """Handler for Help Intent."""

    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return ask_utils.is_intent_name("AMAZON.HelpIntent")(handler_input)

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response

        speak_output = "The Pomodoro Technique is a time management method developed by Francesco Cirillo in the late 1980s. It uses a timer to break work into intervals, typically 25 minutes in length, separated by short breaks."

        return (
            handler_input.response_builder
                .speak(speak_output)
                .ask(speak_output)
                .response
        )


class CancelOrStopIntentHandler(AbstractRequestHandler):
    """Single handler for Cancel and Stop Intent."""

    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return (ask_utils.is_intent_name("AMAZON.CancelIntent")(handler_input) or
                ask_utils.is_intent_name("AMAZON.StopIntent")(handler_input))

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response
        speak_output = "Goodbye!"

        return (
            handler_input.response_builder
                .speak(speak_output)
                .response
        )


class SessionEndedRequestHandler(AbstractRequestHandler):
    """Handler for Session End."""

    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return ask_utils.is_request_type("SessionEndedRequest")(handler_input)

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response

        # Any cleanup logic goes here.

        return handler_input.response_builder.response


class IntentReflectorHandler(AbstractRequestHandler):
    """The intent reflector is used for interaction model testing and debugging.
    It will simply repeat the intent the user said. You can create custom handlers
    for your intents by defining them above, then also adding them to the request
    handler chain below.
    """

    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return ask_utils.is_request_type("IntentRequest")(handler_input)

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response
        intent_name = ask_utils.get_intent_name(handler_input)
        speak_output = "You just triggered " + intent_name + "."

        return (
            handler_input.response_builder
                .speak(speak_output)
                # .ask("add a reprompt if you want to keep the session open for the user to respond")
                .response
        )


class CatchAllExceptionHandler(AbstractExceptionHandler):
    """Generic error handling to capture any syntax or routing errors. If you receive an error
    stating the request handler chain is not found, you have not implemented a handler for
    the intent being invoked or included it in the skill builder below.
    """

    def can_handle(self, handler_input, exception):
        # type: (HandlerInput, Exception) -> bool
        return True

    def handle(self, handler_input, exception):
        # type: (HandlerInput, Exception) -> Response
        logger.error(exception, exc_info=True)

        speak_output = "Sorry, I had trouble doing what you asked. Please try again."

        return (
            handler_input.response_builder
                .speak(speak_output)
                .ask(speak_output)
                .response
        )


# The SkillBuilder object acts as the entry point for your skill, routing all request and response
# payloads to the handlers above. Make sure any new handlers or interceptors you've
# defined are included below. The order matters - they're processed top to bottom.


# sb = SkillBuilder()
# sb = CustomSkillBuilder(api_client=DefaultApiClient())
sb = CustomSkillBuilder(persistence_adapter = dynamodb_adapter, api_client=DefaultApiClient())

sb.add_request_handler(LaunchRequestHandler())

sb.add_request_handler(TimerIntentHandler())
sb.add_request_handler(AcceptGrantResponseHandler())
sb.add_request_handler(ConnectionsResponsehandler())
sb.add_request_handler(SessionResumedHandlerRequest())

sb.add_request_handler(PomodoroIntentHandler())
sb.add_request_handler(HelpIntentHandler())
sb.add_request_handler(PauseIntentHandler())
sb.add_request_handler(ResumeIntentHandler())
sb.add_request_handler(CustomIntervalIntentHandler())
sb.add_request_handler(CancelOrStopIntentHandler())
sb.add_request_handler(SessionEndedRequestHandler())
sb.add_request_handler(
    IntentReflectorHandler())  # make sure IntentReflectorHandler is last so it doesn't override your custom intent handlers

sb.add_exception_handler(CatchAllExceptionHandler())

lambda_handler = sb.lambda_handler()