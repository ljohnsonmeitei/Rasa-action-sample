from typing import Any, Text, Dict, List,Union
from rasa_sdk import Action, Tracker
from rasa_sdk.executor import CollectingDispatcher
from rasa_sdk.events import AllSlotsReset
from rasa_sdk.events import SlotSet
from rasa_sdk.forms import FormAction
import os
import re
import requests
import json
import csv
import datetime as dt
from datetime import timedelta
import base64
from datetime import datetime
import time
import pymongo
from pymongo import MongoClient
from bson.objectid import ObjectId
#from dateparser.search import search_dates
from rasa_sdk.events import (
    SlotSet,
    UserUtteranceReverted,
    ConversationPaused,
    EventType,
    FollowupAction,
)
cert=os.environ.get('PY_CERTS')
env=os.environ.get('NODE_ENV')
cert_root=os.environ.get('NODE_EXTRA_CA_CERTS')
#env=env.upper()

cert_root = cert = False
 
if env=="SIT":
 config_url='https://sit-interlock.anthem.com/pyutilconfig/rasaserver-sit.json'  
elif env=="UAT":
 config_url='https://uat-interlock.anthem.com/pyutilconfig/rasaserver-uat.json'
elif env=="PERF":
 config_url='https://uat-interlock.anthem.com/pyutilconfig/rasaserver-perf.json'
elif env=="PROD":
 config_url='https://prod-interlock.anthem.com/pyutilconfig/rasaserver-prod.json'
elif env=="STAGING":
 config_url='https://prod-interlock.anthem.com/pyutilconfig/rasaserver-staging.json'
else:
 config_url='https://sit-interlock.anthem.com/pyutilconfig/rasaserver-sit.json'  

config_resp=requests.get(url=config_url,verify = cert)
config_resp=config_resp.json()

class actionIncident(Action):
    
    def name(self) -> Text:
         return "action_incident"
    def run(self, dispatcher: CollectingDispatcher,
            tracker: Tracker,
            domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        import requests
        import json
        inc_num=tracker.get_slot('inc_num')
        comment=tracker.get_slot('comments')
        action=tracker.get_slot('actionticket')
        inc_detection=tracker.get_slot('inc_detection')
        resolution_category=tracker.get_slot('resolution_category')
        resolution_code=tracker.get_slot('resolution_code')
        incident_auth_key=config_resp['INCIDNET_APIKEY']
        user_id=tracker.sender_id

        if action.lower() == 'update':

          url = config_resp['INCIDENT_ENDPOINT']
          payload = {
             'number':'{}'.format(inc_num),
             'comments':user_id+ ': ' +comment
             }

          payload=json.dumps(payload)

          headers = {
              'Authorization': incident_auth_key,
              'Content-Type': 'application/json',
             } 

          try:
                 response = requests.request("POST", url, headers=headers, data = payload)
                 if (response.status_code == 201) or (response.status_code == 200):
                       var1=response.json()
                       var2=var1["result"][0]["status"]
                       if var2 == "updated":
                              dispatcher.utter_message("The Incident is updated for Incident number:{}".format(var1["result"][0]["display_value"]))
                       else:
                              dispatcher.utter_message("The Incident is not updated")
                 else:
                      dispatcher.utter_message("Bad response")
          except Exception as e:
                  dispatcher.utter_message('Something went wrong Please try Again')
          return [AllSlotsReset()]

        elif action.lower() == 'close':

          url = config_resp['INCIDENT_ENDPOINT']

          payload = {
              'number':'{}'.format(inc_num),  
              'state':'6',
              'u_incident_detection':inc_detection,
              'u_resolution_sub_code':resolution_code,
              'close_code':resolution_category,
              'close_notes':user_id+ ': ' +comment
              }

          payload=json.dumps(payload)

          headers = {
              'Authorization': incident_auth_key,
              'Content-Type': 'application/json',
             } 

          try:
                  response = requests.request("POST", url, headers=headers, data = payload)
                  if (response.status_code == 201) or (response.status_code == 200):
                       var1=response.json()
                       var2=var1["result"][0]["status"]
                    
                       if var2 != '':
                               dispatcher.utter_message("The Incident is closed for Incident number:{}".format(var1["result"][0]["display_value"]))
                       else:
                               dispatcher.utter_message("The Incident is not closed")
                  else:
                      dispatcher.utter_message("Bad response")
          except Exception as e:
              dispatcher.utter_message('Something went wrong Please try Again')
          return [AllSlotsReset()]

class actionRescdedropdown(Action):
    
    def name(self) -> Text:
         return "action_rescde"
    def run(self, dispatcher: CollectingDispatcher,
            tracker: Tracker,
            domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        
        resolution_category=tracker.get_slot('resolution_category')

        if resolution_category == 'Application':

          data=[{"label":"No Action Taken","value":'/inform{     \"resolution_code\": \"No Action Taken\"   }'},{"label":"No Customer Response","value":'/inform{     \"resolution_code\": \"No Customer Response\"   }'},{"label":"Code Fixed","value":'/inform{     \"resolution_code\": \"Code Fixed\"   }'},{"label":"Certificate Renewed","value":'/inform{     \"resolution_code\": \"Certificate Renewed\"   }'},{"label":"Certificate Re-Installed","value":'/inform{     \"resolution_code\": \"Certificate Re-Installed\"   }'},{"label":"Configuration Modified","value":'/inform{     \"resolution_code\": \"Configuration Modified\"   }'},{"label":"Data Modified or Corrected","value":'/inform{     \"resolution_code\": \"Data Modified or Corrected\"   }'},{"label":"Capacity Increased","value":'/inform{     \"resolution_code\": \"Capacity Increased\"   }'},{"label":"JVM Recycled","value":'/inform{     \"resolution_code\": \"JVM Recycled\"   }'},{"label":"Application Server Recycled","value":'/inform{     \"resolution_code\": \"Application Server Recycled\"   }'},{"label":"Application Service Recycled/Restarted","value":'/inform{     \"resolution_code\": \"Application Service Recycled/Restarted\"   }'},{"label":"MQ Manger Restarted","value":'/inform{     \"resolution_code\": \"MQ Manger Restarted\"   }'},{"label":"MQ Channel Restarted","value":'/inform{     \"resolution_code\": \"MQ Channel Restarted\"   }'},{"label":"MQ Channel Cleared","value":'/inform{     \"resolution_code\": \"MQ Channel Cleared\"   }'},{"label":"Web Server Recycled","value":'/inform{     \"resolution_code\": \"Web Server Recycled\"   }'},{"label":"Change Backed Out","value":'/inform{     \"resolution_code\": \"Change Backed Out\"   }'},{"label":"Failover Performed","value":'/inform{     \"resolution_code\": \"Failover Performed\"   }'},{"label":"License Renewed/Added","value":'/inform{     \"resolution_code\": \"License Renewed/Added\"   }'},{"label":"Restore from Backup","value":'/inform{     \"resolution_code\": \"Restore from Backup\"   }'},{"label":"Vendor Change Completed","value":'/inform{     \"resolution_code\": \"Vendor Change Completed\"   }'},{"label":"Vendor Change backed out","value":'/inform{     \"resolution_code\": \"Vendor Change backed out\"   }'},{"label":"Vendor Incident resolved","value":'/inform{     \"resolution_code\": \"Vendor Incident resolved\"   }'},{"label":"Planned Change Completed","value":'/inform{     \"resolution_code\": \"Planned Change Completed\"   }'},{"label":"Resolution Undetermined","value":'/inform{     \"resolution_code\": \"Resolution Undetermined\"   }'},{"label":"Monitoring Tool Reset","value":'/inform{     \"resolution_code\": \"Monitoring Tool Reset\"   }'},{"label":"No Resolution listed","value":'/inform{     \"resolution_code\": \"No Resolution listed\"   }'},{"label":"Dependent backend System Issue resolved","value":'/inform{     \"resolution_code\": \"Dependent backend System Issue resolved\"   }'}]
        
        if resolution_category == 'Distributed Operations':

          data=[{"label":"No Action Taken","value":'/inform{     \"resolution_code\": \"No Action Taken\"   }'},{"label":"No Customer Response","value":'/inform{     \"resolution_code\": \"No Customer Response\"   }'},{"label":"Batch Job Rerun","value":'/inform{     \"resolution_code\": \"Batch Job Rerun\"   }'},{"label":"Batch Job Canceled","value":'/inform{     \"resolution_code\": \"Batch Job Canceled\"   }'},{"label":"Batch Code Modified","value":'/inform{     \"resolution_code\": \"Batch Code Modified\"   }'},{"label":"Restore from Backup","value":'/inform{     \"resolution_code\": \"Restore from Backup\"   }'},{"label":"Replaced Hardware","value":'/inform{     \"resolution_code\": \"Replaced Hardware\"   }'},{"label":"Hardware Reseated","value":'/inform{     \"resolution_code\": \"Hardware Reseated\"   }'},{"label":"Monitoring Tool Reset","value":'/inform{     \"resolution_code\": \"Monitoring Tool Reset\"   }'},{"label":"Planned Change Completed","value":'/inform{     \"resolution_code\": \"Planned Change Completed\"   }'},{"label":"Change Backed out","value":'/inform{     \"resolution_code\": \"Change Backed out\"   }'},{"label":"Vendor Change Completed","value":'/inform{     \"resolution_code\": \"Vendor Change Completed\"   }'},{"label":"Vendor Change backed out","value":'/inform{     \"resolution_code\": \"Vendor Change backed out\"   }'},{"label":"Vendor Incident Resolved","value":'/inform{     \"resolution_code\": \"Vendor Incident Resolved\"   }'},{"label":"No Resolution Listed","value":'/inform{     \"resolution_code\": \"No Resolution Listed\"   }'},{"label":"Resolution Undetermined","value":'/inform{     \"resolution_code\": \"Resolution Undetermined\"   }'}]

        if resolution_category == 'Account Security':

          data=[{"label":"No Action Taken","value":'/inform{     \"resolution_code\": \"No Action Taken\"   }'},{"label":"No Customer Response","value":'/inform{     \"resolution_code\": \"No Customer Response\"   }'},{"label":"Account Unlock","value":'/inform{     \"resolution_code\": \"Account Unlock\"   }'},{"label":"Account Unlock –Recurring","value":'/inform{     \"resolution_code\": \"Account Unlock –Recurring\"   }'},{"label":"HOT ID Provided","value":'/inform{     \"resolution_code\": \"HOT ID Provided\"   }'},{"label":"Password Reset","value":'/inform{     \"resolution_code\": \"Password Reset\"   }'},{"label":"Password Reset/Account Unlock","value":'/inform{     \"resolution_code\": \"Password Reset/Account Unlock\"   }'},{"label":"PIN Verification Failure","value":'/inform{     \"resolution_code\": \"PIN Verification Failure\"   }'},{"label":"Resolution Undetermined","value":'/inform{     \"resolution_code\": \"Resolution Undetermined\"   }'}]

        if resolution_category == 'End User Hardware':

          data=[{"label":"No Action Taken","value":'/inform{     \"resolution_code\": \"No Action Taken\"   }'},{"label":"No Customer Response","value":'/inform{     \"resolution_code\": \"No Customer Response\"   }'},{"label":"BIOS Upgrade","value":'/inform{     \"resolution_code\": \"BIOS Upgrade\"   }'},{"label":"Cable Reconnected/Replaced","value":'/inform{     \"resolution_code\": \"Cable Reconnected/Replaced\"   }'},{"label":"Conference Room Repair","value":'/inform{     \"resolution_code\": \"Conference Room Repair\"   }'},{"label":"Device-Reimage","value":'/inform{     \"resolution_code\": \"Device-Reimage\"   }'},{"label":"Device-Repair","value":'/inform{     \"resolution_code\": \"Device-Repair\"   }'},{"label":"Device-Replace","value":'/inform{     \"resolution_code\": \"Device-Replace\"   }'},{"label":"Device-Upgrade","value":'/inform{     \"resolution_code\": \"Device-Upgrade\"   }'},{"label":"Driver Update","value":'/inform{     \"resolution_code\": \"Driver Update\"   }'},{"label":"How To Assistance","value":'/inform{     \"resolution_code\": \"How To Assistance\"   }'},{"label":"OS Patch Applied","value":'/inform{     \"resolution_code\": \"OS Patch Applied\"   }'},{"label":"Peripheral-Repair","value":'/inform{     \"resolution_code\": \"Peripheral-Repair\"   }'},{"label":"Peripheral-Replace","value":'/inform{     \"resolution_code\": \"Peripheral-Replace\"   }'},{"label":"Power Cycle","value":'/inform{     \"resolution_code\": \"Power Cycle\"   }'},{"label":"Resolution Undetermined","value":'/inform{     \"resolution_code\": \"Resolution Undetermined\"   }'}]

        if resolution_category == 'End User Support':

          data=[{"label":"No Action Taken","value":'/inform{     \"resolution_code\": \"No Action Taken\"   }'},{"label":"No Customer Response","value":'/inform{     \"resolution_code\": \"No Customer Response\"   }'},{"label":"Settings Change","value":'/inform{     \"resolution_code\": \"Settings Change\"   }'},{"label":"Call Transfer","value":'/inform{     \"resolution_code\": \"Call Transfer\"   }'},{"label":"File Restore Performed","value":'/inform{     \"resolution_code\": \"File Restore Performed\"   }'},{"label":"How To Assistance","value":'/inform{     \"resolution_code\": \"How To Assistance\"   }'},{"label":"IT ServiceConnect Referral","value":'/inform{     \"resolution_code\": \"IT ServiceConnect Referral\"   }'},{"label":"Map-Drive/Network Share","value":'/inform{     \"resolution_code\": \"Map-Drive/Network Share\"   }'},{"label":"Map-Printer","value":'/inform{     \"resolution_code\": \"Map-Printer\"   }'},{"label":"Network Settings Change","value":'/inform{     \"resolution_code\": \"Network Settings Change\"   }'},{"label":"OS-Configuration Change","value":'/inform{     \"resolution_code\": \"OS-Configuration Change\"   }'},{"label":"Power Cycle","value":'/inform{     \"resolution_code\": \"Power Cycle\"   }'},{"label":"Software-Configuration Change","value":'/inform{     \"resolution_code\": \"Software-Configuration Change\"   }'},{"label":"Software-Install","value":'/inform{     \"resolution_code\": \"Software-Install\"   }'},{"label":"Software-Reinstall","value":'/inform{     \"resolution_code\": \"Software-Reinstall\"   }'},{"label":"Software-Repair","value":'/inform{     \"resolution_code\": \"Software-Repair\"   }'},{"label":"Ticket Status Provided","value":'/inform{     \"resolution_code\": \"Ticket Status Provided\"   }'},{"label":"Virus/Malware Removal","value":'/inform{     \"resolution_code\": \"Virus/Malware Removal\"   }'},{"label":"Resolution Undetermined","value":'/inform{     \"resolution_code\": \"Resolution Undetermined\"   }'}]

        if resolution_category == 'Facilities':

          data=[{"label":"No Action Taken","value":'/inform{     \"resolution_code\": \"No Action Taken\"   }'},{"label":"No Customer Response","value":'/inform{     \"resolution_code\": \"No Customer Response\"   }'},{"label":"Utility Power Restored","value":'/inform{     \"resolution_code\": \"Utility Power Restored\"   }'},{"label":"Building Power Restored","value":'/inform{     \"resolution_code\": \"Building Power Restored\"   }'},{"label":"Temperature Stabilized","value":'/inform{     \"resolution_code\": \"Temperature Stabilized\"   }'},{"label":"UPS Batteries Replaced","value":'/inform{     \"resolution_code\": \"UPS Batteries Replaced\"   }'},{"label":"Hardware Replaced","value":'/inform{     \"resolution_code\": \"Hardware Replaced\"   }'},{"label":"Failover Performed","value":'/inform{     \"resolution_code\": \"Failover Performed\"   }'},{"label":"Planned Change Completed","value":'/inform{     \"resolution_code\": \"Planned Change Completed\"   }'},{"label":"Monitoring Tool Reset","value":'/inform{     \"resolution_code\": \"Monitoring Tool Reset\"   }'},{"label":"Change Backed out","value":'/inform{     \"resolution_code\": \"Change Backed out\"   }'},{"label":"No Resolution Listed","value":'/inform{     \"resolution_code\": \"No Resolution Listed\"   }'},{"label":"Resolution Undetermined","value":'/inform{     \"resolution_code\": \"Resolution Undetermined\"   }'}]

        if resolution_category == 'Mainframe Operations':

          data=[{"label":"No Action Taken","value":'/inform{     \"resolution_code\": \"No Action Taken\"   }'},{"label":"No Customer Response","value":'/inform{     \"resolution_code\": \"No Customer Response\"   }'},{"label":"Batch Code Modified","value":'/inform{     \"resolution_code\": \"Batch Code Modified\"   }'},{"label":"Batch Job Canceled","value":'/inform{     \"resolution_code\": \"Batch Job Canceled\"   }'},{"label":"Batch Job Rerun","value":'/inform{     \"resolution_code\": \"Batch Job Rerun\"   }'},{"label":"Capacity Added Memory","value":'/inform{     \"resolution_code\": \"Capacity Added Memory\"   }'},{"label":"Capacity Added Storage","value":'/inform{     \"resolution_code\": \"Capacity Added Storage\"   }'},{"label":"Change Backed out","value":'/inform{     \"resolution_code\": \"Change Backed out\"   }'},{"label":"Communications Restored TCPIP","value":'/inform{     \"resolution_code\": \"Communications Restored TCPIP\"   }'},{"label":"Communications Restored VTAM","value":'/inform{     \"resolution_code\": \"Communications Restored VTAM\"   }'},{"label":"Hardware Reseated","value":'/inform{     \"resolution_code\": \"Hardware Reseated\"   }'},{"label":"Monitoring Tool Reset","value":'/inform{     \"resolution_code\": \"Monitoring Tool Reset\"   }'},{"label":"MQ Channel Cleared","value":'/inform{     \"resolution_code\": \"MQ Channel Cleared\"   }'},{"label":"MQ Channel Restarted","value":'/inform{     \"resolution_code\": \"MQ Channel Restarted\"   }'},{"label":"MQ Manager Restarted","value":'/inform{     \"resolution_code\": \"MQ Manager Restarted\"   }'},{"label":"No Resolution Listed","value":'/inform{     \"resolution_code\": \"No Resolution Listed\"   }'},{"label":"Region Restarted","value":'/inform{     \"resolution_code\": \"Region Restarted\"   }'},{"label":"Replaced Hardware","value":'/inform{     \"resolution_code\": \"Replaced Hardware\"   }'},{"label":"Resolution Undetermined","value":'/inform{     \"resolution_code\": \"Resolution Undetermined\"   }'},{"label":"System Job Stopped","value":'/inform{     \"resolution_code\": \"System Job Stopped\"   }'},{"label":"System or Program code modified","value":'/inform{     \"resolution_code\": \"System or Program code modified\"   }'},{"label":"Transaction Restarted","value":'/inform{     \"resolution_code\": \"Transaction Restarted\"   }'},{"label":"Transaction Stopped","value":'/inform{     \"resolution_code\": \"Transaction Stopped\"   }'},{"label":"User Job Stopped","value":'/inform{     \"resolution_code\": \"User Job Stopped\"   }'},{"label":"Vendor Change completed","value":'/inform{     \"resolution_code\": \"Vendor Change completed\"   }'},{"label":"Vendor Change backed out","value":'/inform{     \"resolution_code\": \"Vendor Change backed out\"   }'},{"label":"Vendor Incident resolved","value":'/inform{     \"resolution_code\": \"Vendor Incident resolved\"   }'}]

        if resolution_category == 'Network':

          data=[{"label":"No Action Taken","value":'/inform{     \"resolution_code\": \"No Action Taken\"   }'},{"label":"No Customer Response","value":'/inform{     \"resolution_code\": \"No Customer Response\"   }'},{"label":"Replaced Network drive","value":'/inform{     \"resolution_code\": \"Replaced Network drive\"   }'},{"label":"Circuit Restored","value":'/inform{     \"resolution_code\": \"Circuit Restored\"   }'},{"label":"Vendor Circuit Restored","value":'/inform{     \"resolution_code\": \"Vendor Circuit Restored\"   }'},{"label":"Capacity Added Bandwidth","value":'/inform{     \"resolution_code\": \"Capacity Added Bandwidth\"   }'},{"label":"Traffic Rerouted","value":'/inform{     \"resolution_code\": \"Traffic Rerouted\"   }'},{"label":"Card Replaced","value":'/inform{     \"resolution_code\": \"Card Replaced\"   }'},{"label":"Module Replaced","value":'/inform{     \"resolution_code\": \"Module Replaced\"   }'},{"label":"Power Supply Replaced","value":'/inform{     \"resolution_code\": \"Power Supply Replaced\"   }'},{"label":"UPS Batteries Replaced","value":'/inform{     \"resolution_code\": \"UPS Batteries Replaced\"   }'},{"label":"IOS Configuration Modified","value":'/inform{     \"resolution_code\": \"IOS Configuration Modified\"   }'},{"label":"Firmware Upgraded","value":'/inform{     \"resolution_code\": \"Firmware Upgraded\"   }'},{"label":"Network Hardware Reseated","value":'/inform{     \"resolution_code\": \"Network Hardware Reseated\"   }'},{"label":"Device Recycled","value":'/inform{     \"resolution_code\": \"Device Recycled\"   }'},{"label":"Failover Performed","value":'/inform{     \"resolution_code\": \"Failover Performed\"   }'},{"label":"Restart without Intervention","value":'/inform{     \"resolution_code\": \"Restart without Intervention\"   }'},{"label":"Vendor Change completed","value":'/inform{     \"resolution_code\": \"Vendor Change completed\"   }'},{"label":"Vendor Change backed out","value":'/inform{     \"resolution_code\": \"Vendor Change backed out\"   }'},{"label":"Vendor Incident resolved","value":'/inform{     \"resolution_code\": \"Vendor Incident resolved\"   }'},{"label":"Change backed out","value":'/inform{     \"resolution_code\": \"Change backed out\"   }'},{"label":"Routing Configuration Modified","value":'/inform{     \"resolution_code\": \"Routing Configuration Modified\"   }'},{"label":"Planned Change Completed","value":'/inform{     \"resolution_code\": \"Planned Change Completed\"   }'},{"label":"Resolution Undetermined","value":'/inform{     \"resolution_code\": \"Resolution Undetermined\"   }'},{"label":"Monitoring Tool Reset","value":'/inform{     \"resolution_code\": \"Monitoring Tool Reset\"   }'},{"label":"No Resolution Listed","value":'/inform{     \"resolution_code\": \"No Resolution Listed\"   }'}]

        if resolution_category == 'Voice':

          data=[{"label":"No Action Taken","value":'/inform{     \"resolution_code\": \"No Action Taken\"   }'},{"label":"No Customer Response","value":'/inform{     \"resolution_code\": \"No Customer Response\"   }'},{"label":"Voice Circuit Restored","value":'/inform{     \"resolution_code\": \"Voice Circuit Restored\"   }'},{"label":"Voice Vendor Circuit Restored","value":'/inform{     \"resolution_code\": \"Voice Vendor Circuit Restored\"   }'},{"label":"Voice Traffic Rerouted","value":'/inform{     \"resolution_code\": \"Voice Traffic Rerouted\"   }'},{"label":"Voice Card Replaced","value":'/inform{     \"resolution_code\": \"Voice Card Replaced\"   }'},{"label":"Voice Card Replaced","value":'/inform{     \"resolution_code\": \"Voice Module Replaced\"   }'},{"label":"Voice Card Disabled","value":'/inform{     \"resolution_code\": \"Voice Card Disabled\"   }'},{"label":"Voice Configuration Changed/Modified","value":'/inform{     \"resolution_code\": \"Voice Configuration Changed/Modified\"   }'},{"label":"Voice Hardware Reseated","value":'/inform{     \"resolution_code\": \"Voice Hardware Reseated\"   }'},{"label":"Power Supply Replaced","value":'/inform{     \"resolution_code\": \"Power Supply Replaced\"   }'},{"label":"Failover Performed","value":'/inform{     \"resolution_code\": \"Failover Performed\"   }'},{"label":"Firmware Upgraded","value":'/inform{     \"resolution_code\": \"Firmware Upgraded\"   }'},{"label":"Voice Device Recycled","value":'/inform{     \"resolution_code\": \"Voice Device Recycled\"   }'},{"label":"Restart without Intervention","value":'/inform{     \"resolution_code\": \"Restart without Intervention\"   }'},{"label":"Vendor Change backed out","value":'/inform{     \"resolution_code\": \"Vendor Change backed out\"   }'},{"label":"Vendor Incident resolved","value":'/inform{     \"resolution_code\": \"Vendor Incident resolved\"   }'},{"label":"Change backed out","value":'/inform{     \"resolution_code\": \"Change backed out\"   }'},{"label":"Routing Configuration Modified","value":'/inform{     \"resolution_code\": \"Routing Configuration Modified\"   }'},{"label":"Resolution Undetermined","value":'/inform{     \"resolution_code\": \"Resolution Undetermined\"   }'},{"label":"Monitoring Tool Reset","value":'/inform{     \"resolution_code\": \"Monitoring Tool Reset\"   }'},{"label":"No Resolution Listed","value":'/inform{     \"resolution_code\": \"No Resolution Listed\"   }'}]

        if resolution_category == 'Server':

          data=[{"label":"No Action Taken","value":'/inform{     \"resolution_code\": \"No Action Taken\"   }'},{"label":"No Customer Response","value":'/inform{     \"resolution_code\": \"No Customer Response\"   }'},{"label":"Server Powered On","value":'/inform{     \"resolution_code\": \"Server Powered On\"   }'},{"label":"Recycle Performed","value":'/inform{     \"resolution_code\": \"Recycle Performed\"   }'},{"label":"Replaced Hardware","value":'/inform{     \"resolution_code\": \"Replaced Hardware\"   }'},{"label":"Hardware Reseated","value":'/inform{     \"resolution_code\": \"Hardware Reseated\"   }'},{"label":"Capacity Added Memory","value":'/inform{     \"resolution_code\": \"Capacity Added Memory\"   }'},{"label":"Capacity Added Storage","value":'/inform{     \"resolution_code\": \"Capacity Added Storage\"   }'},{"label":"Reloaded Operating System","value":'/inform{     \"resolution_code\": \"Reloaded Operating System\"   }'},{"label":"OS Configuration Changes","value":'/inform{     \"resolution_code\": \"OS Configuration Changes\"   }'},{"label":"Disk Space Cleared","value":'/inform{     \"resolution_code\": \"Disk Space Cleared\"   }'},{"label":"Service Restarted","value":'/inform{     \"resolution_code\": \"Service Restarted\"   }'},{"label":"Restore from Backup","value":'/inform{     \"resolution_code\": \"Restore from Backup\"   }'},{"label":"Failover Performed","value":'/inform{     \"resolution_code\": \"Failover Performed\"   }'},{"label":"Restart without Manual Intervention","value":'/inform{     \"resolution_code\": \"Restart without Manual Intervention\"   }'},{"label":"Anti Virus Modification","value":'/inform{     \"resolution_code\": \"Anti Virus Modification\"   }'},{"label":"Planned Change Completed","value":'/inform{     \"resolution_code\": \"Planned Change Completed\"   }'},{"label":"Change backed out","value":'/inform{     \"resolution_code\": \"Change backed out\"   }'},{"label":"Routing Configuration Modified","value":'/inform{     \"resolution_code\": \"Routing Configuration Modified\"   }'},{"label":"Resolution Undetermined","value":'/inform{     \"resolution_code\": \"Resolution Undetermined\"   }'},{"label":"Monitoring Tool Reset","value":'/inform{     \"resolution_code\": \"Monitoring Tool Reset\"   }'},{"label":"No Resolution Listed","value":'/inform{     \"resolution_code\": \"No Resolution Listed\"   }'}]

        if resolution_category == 'Storage':

          data=[{"label":"No Action Taken","value":'/inform{     \"resolution_code\": \"No Action Taken\"   }'},{"label":"No Customer Response","value":'/inform{     \"resolution_code\": \"No Customer Response\"   }'},{"label":"SAN Storage Added","value":'/inform{     \"resolution_code\": \"SAN Storage Added\"   }'},{"label":"SAN Port Blocked","value":'/inform{     \"resolution_code\": \"SAN Port Blocked\"   }'},{"label":"SAN Controller Reconfigured","value":'/inform{     \"resolution_code\": \"SAN Controller Reconfigured\"   }'},{"label":"SAN Hardware Replaced","value":'/inform{     \"resolution_code\": \"SAN Hardware Replaced\"   }'},{"label":"Storage Space Cleared","value":'/inform{     \"resolution_code\": \"Storage Space Cleared\"   }'},{"label":"NAS Recycled","value":'/inform{     \"resolution_code\": \"NAS Recycled\"   }'},{"label":"NAS Hardware Replaced","value":'/inform{     \"resolution_code\": \"NAS Hardware Replaced\"   }'},{"label":"Restore from Backup","value":'/inform{     \"resolution_code\": \"Restore from Backup\"   }'},{"label":"Failover Performed","value":'/inform{     \"resolution_code\": \"Failover Performed\"   }'},{"label":"Planned Change Completed","value":'/inform{     \"resolution_code\": \"Planned Change Completed\"   }'},{"label":"Change backed out","value":'/inform{     \"resolution_code\": \"Change backed out\"   }'},{"label":"Routing Configuration Modified","value":'/inform{     \"resolution_code\": \"Routing Configuration Modified\"   }'},{"label":"Resolution Undetermined","value":'/inform{     \"resolution_code\": \"Resolution Undetermined\"   }'},{"label":"Monitoring Tool Reset","value":'/inform{     \"resolution_code\": \"Monitoring Tool Reset\"   }'},{"label":"No Resolution Listed","value":'/inform{     \"resolution_code\": \"No Resolution Listed\"   }'}]

        if resolution_category == 'Security':

          data=[{"label":"No Action Taken","value":'/inform{     \"resolution_code\": \"No Action Taken\"   }'},{"label":"No Customer Response","value":'/inform{     \"resolution_code\": \"No Customer Response\"   }'},{"label":"Activity Verified","value":'/inform{     \"resolution_code\": \"Activity Verified\"   }'},{"label":"Certificated Renewed","value":'/inform{     \"resolution_code\": \"Certificated Renewed\"   }'},{"label":"Certificate Re-Installed","value":'/inform{     \"resolution_code\": \"Certificate Re-Installed\"   }'},{"label":"Security Account Locked","value":'/inform{     \"resolution_code\": \"Security Account Locked\"   }'},{"label":"Group Security Reconfigured","value":'/inform{     \"resolution_code\": \"Group Security Reconfigured\"   }'},{"label":"Group Security Restored","value":'/inform{     \"resolution_code\": \"Group Security Restored\"   }'},{"label":"Security Threat Remediated","value":'/inform{     \"resolution_code\": \"Security Threat Remediated\"   }'},{"label":"Planned Change Completed","value":'/inform{     \"resolution_code\": \"Planned Change Completed\"   }'},{"label":"Change backed out","value":'/inform{     \"resolution_code\": \"Change backed out\"   }'},{"label":"Routing Configuration Modified","value":'/inform{     \"resolution_code\": \"Routing Configuration Modified\"   }'},{"label":"Resolution Undetermined","value":'/inform{     \"resolution_code\": \"Resolution Undetermined\"   }'},{"label":"Monitoring Tool Reset","value":'/inform{     \"resolution_code\": \"Monitoring Tool Reset\"   }'},{"label":"No Resolution Listed","value":'/inform{     \"resolution_code\": \"No Resolution Listed\"   }'}]

        if resolution_category == 'DataBase':

          data=[{"label":"No Action Taken","value":'/inform{     \"resolution_code\": \"No Action Taken\"   }'},{"label":"No Customer Response","value":'/inform{     \"resolution_code\": \"No Customer Response\"   }'},{"label":"Database restarted","value":'/inform{     \"resolution_code\": \"Database restarted\"   }'},{"label":"Database Service Restarted","value":'/inform{     \"resolution_code\": \"Database Service Restarted\"   }'},{"label":"Database Configuration Modified","value":'/inform{     \"resolution_code\": \"Database Configuration Modified\"   }'},{"label":"Database Query Correction","value":'/inform{     \"resolution_code\": \"Database Query Correction\"   }'},{"label":"Database Optimization","value":'/inform{     \"resolution_code\": \"Database Optimization\"   }'},{"label":"Restore from Backup","value":'/inform{     \"resolution_code\": \"Restore from Backup\"   }'},{"label":"Restore without Intervention","value":'/inform{     \"resolution_code\": \"Restore without Intervention\"   }'},{"label":"Failover Performed","value":'/inform{     \"resolution_code\": \"Failover Performed\"   }'},{"label":"Planned Change Completed","value":'/inform{     \"resolution_code\": \"Planned Change Completed\"   }'},{"label":"Change backed out","value":'/inform{     \"resolution_code\": \"Change backed out\"   }'},{"label":"Routing Configuration Modified","value":'/inform{     \"resolution_code\": \"Routing Configuration Modified\"   }'},{"label":"Resolution Undetermined","value":'/inform{     \"resolution_code\": \"Resolution Undetermined\"   }'},{"label":"Monitoring Tool Reset","value":'/inform{     \"resolution_code\": \"Monitoring Tool Reset\"   }'},{"label":"No Resolution Listed","value":'/inform{     \"resolution_code\": \"No Resolution Listed\"   }'}]

        if resolution_category == 'Storage Backup Support':

          data=[{"label":"No Action Taken","value":'/inform{     \"resolution_code\": \"No Action Taken\"   }'},{"label":"No Customer Response","value":'/inform{     \"resolution_code\": \"No Customer Response\"   }'},{"label":"Backup infrastructure Hardware/Software Recycled/Rebooted","value":'/inform{     \"resolution_code\": \"Backup infrastructure Hardware/Software Recycled/Rebooted\"   }'},{"label":"Permission Remediated","value":'/inform{     \"resolution_code\": \"Permission Remediated\"   }'},{"label":"VMware setting changed/reset","value":'/inform{     \"resolution_code\": \"VMware setting changed/reset\"   }'},{"label":"Backup Client Software reset/installed, upgraded","value":'/inform{     \"resolution_code\": \"Backup Client Software reset/installed, upgraded\"   }'},{"label":"External Condition remediated","value":'/inform{     \"resolution_code\": \"External Condition remediated\"   }'},{"label":"Backup taken/Restore Completed","value":'/inform{     \"resolution_code\": \"Backup taken/Restore Completed\"   }'},{"label":"Planned Change Completed","value":'/inform{     \"resolution_code\": \"Planned Change Completed\"   }'},{"label":"Change backed out","value":'/inform{     \"resolution_code\": \"Change backed out\"   }'},{"label":"Routing Configuration Modified","value":'/inform{     \"resolution_code\": \"Routing Configuration Modified\"   }'},{"label":"Resolution Undetermined","value":'/inform{     \"resolution_code\": \"Resolution Undetermined\"   }'},{"label":"Monitoring Tool Reset","value":'/inform{     \"resolution_code\": \"Monitoring Tool Reset\"   }'},{"label":"No Resolution Listed","value":'/inform{     \"resolution_code\": \"No Resolution Listed\"   }'}]

        message={"payload":"dropDown","data":data}

        dispatcher.utter_message(text="Please select the resolution code:",json_message=message)

        return[]

class actionticket(Action):
    
    def name(self) -> Text:
         return "action_incident_ticket_close"
    def run(self, dispatcher: CollectingDispatcher,
            tracker: Tracker,
            domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:

        action=tracker.get_slot('actionticket')

        if action.lower() == 'close':

          buttons = []

          message_title = "Please select incident detection type from the below:"

          buttons.append(
                    {"title": 'Automation', "payload": '/inform_ticket1{"inc_detection": "Automation"}'}
                )

          buttons.append(
                    {"title": 'Support', "payload": '/inform_ticket1{"inc_detection": "Support"}'}
                )

          buttons.append(
                    {"title": 'Not Detected', "payload": '/inform_ticket1{"inc_detection": "Not Detected"}'}
                )

          dispatcher.utter_message(text=message_title, buttons=buttons)

          return[]

        elif action.lower() == 'update':

          return[FollowupAction('action_incident')]

        return[]


class actionRequest(Action):
    
    def name(self) -> Text:
         return "action_request"
    def run(self, dispatcher: CollectingDispatcher,
            tracker: Tracker,
            domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        import requests
        import json
        req_num=tracker.get_slot('req_num')
        sctask_auth_key=config_resp['SCTASK_APIKEY']

        if req_num.strip().startswith('REQ'):

           url = config_resp['REQ_API'] + "={}".format(req_num)


           headers = {
              'Authorization': sctask_auth_key,
              'Content-Type': 'application/json',
             }
           try:
                  response = requests.request("GET", url, headers=headers) 
                  
                  if (response.status_code == 201) or (response.status_code == 200):
                        buttons = []
                        for item in range(0,len(response.json()['result'])):
                         var1=response.json()
                         var2 = var1["result"][item]["number"]
                         sctask_number = var2
                         message_title = (
                                "Below are the sctasks tagged to {}. Please select any and proceed.".format(req_num)
                                )
                         sctask_data={"sctask_num": sctask_number}
                         payloaddata='/inform_ticket{}'.format(json.dumps(sctask_data))
                         buttons.append(
                               {"title": sctask_number, "payload":payloaddata}
                           )
                  else: 
                         dispatcher.utter_message("Bad response")     
                  dispatcher.utter_message(text=message_title, buttons=buttons)
                  return[]

           except Exception as e:
                  dispatcher.utter_message('Something went wrong Please try Again')

        if req_num.startswith('RITM'):

           url = config_resp['RITM_API'] + "={}".format(req_num)


           headers = {
              'Authorization': sctask_auth_key,
              'Content-Type': 'application/json',
             }
           try:
                  response = requests.request("GET", url, headers=headers) 
                
                  if (response.status_code == 201) or (response.status_code == 200):
                        buttons = []
                        for item in range(0,len(response.json()['result'])):
                         var1=response.json()
                         var2 = var1["result"][item]["number"]
                         sctask_number = var2
                         message_title = (
                                "Below are the sctasks tagged to {}. Please select any and proceed.".format(req_num)
                                )
                         sctask_data={"sctask_num": sctask_number}
                         payloaddata='/inform_ticket{}'.format(json.dumps(sctask_data))
                         buttons.append(
                               {"title": sctask_number, "payload":payloaddata}
                           )
                  else: 
                         dispatcher.utter_message("Bad response")  
                  dispatcher.utter_message(text=message_title, buttons=buttons)
                  return[]

           except Exception as e:
                  dispatcher.utter_message('Something went wrong Please try Again')

class actionSctask(Action):
    
    def name(self) -> Text:
         return "action_sctask"
    def run(self, dispatcher: CollectingDispatcher,
            tracker: Tracker,
            domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        import requests
        import json
        sctask_num=tracker.get_slot('sctask_num')
        comment=tracker.get_slot('comments')
        action=tracker.get_slot('actionticket')
        sctask_auth_key=config_resp['SCTASK_APIKEY']
        user_id=tracker.sender_id

        if action.lower() == 'update':

          url = config_resp['SCTASK_ENDPOINT']

          payload = {
              'number':'{}'.format(sctask_num),
              'comments':user_id+ ': ' +comment
              }

          payload=json.dumps(payload)

          headers = {
              'Authorization': sctask_auth_key,
              'Content-Type': 'application/json',
             } 

          try:
                  response = requests.request("POST", url, headers=headers, data = payload)
                  v1 = response.status_code 
                
                  if (response.status_code == 201) or (response.status_code == 200):
                       var1=response.json()
                       var2 = var1["result"][0]["status"]
                       if var2 == "updated":
                              dispatcher.utter_message("The SCTask is updated for:{}".format(var1["result"][0]["display_value"]))
                       else:
                              dispatcher.utter_message("The SCTask is not updated")
                  else: 
                         dispatcher.utter_message("Bad response")
          except Exception as e:
                  dispatcher.utter_message('Something went wrong Please try Again')
          return [AllSlotsReset()]

        elif action.lower() == 'close':

          url = config_resp['SCTASK_ENDPOINT']

          payload = {
              'number':'{}'.format(sctask_num),
              'state':'3',
              'comments':user_id+ ': ' +comment,
              'close_notes':user_id+ ': ' +comment
              }

          payload=json.dumps(payload)

          headers = {
              'Authorization': sctask_auth_key,
              'Content-Type': 'application/json',
             } 

          try:
                 response = requests.request("POST", url, headers=headers, data = payload)
                 if (response.status_code == 201) or (response.status_code == 200):
                       var1=response.json()
                       var2 = var1["result"][0]["status"]
                       if var2 == "updated":
                              dispatcher.utter_message("The SCTask is closed for:{}".format(var1["result"][0]["display_value"]))
                       else:
                              dispatcher.utter_message("The SCTask is not closed")
                 else:
                        dispatcher.utter_message("Bad response")
          except Exception as e:
           dispatcher.utter_message('Something went wrong Please try Again')
        return [AllSlotsReset()]

class Actioncommentform(FormAction):
    def name(self) -> Text:
        return "action_comments"
    @staticmethod
    def required_slots(tracker: Tracker)-> List[Text]:
        return{"comments"}
    def slot_mappings(self) -> Dict[Text, Union[Dict, List[Dict]]]:
    

     return {
        
        "comments": [self.from_text()]
      }

    def submit(
    self,
    dispatcher: CollectingDispatcher,
    tracker: Tracker,
    domain: Dict[Text, Any],
        ) -> List[Dict]:
        
        return []

class Actionticketform(FormAction):
    def name(self) -> Text:
        return "actionticket"
    @staticmethod
    def required_slots(tracker: Tracker)-> List[Text]:
        return{"actionticket"}
    def slot_mappings(self) -> Dict[Text, Union[Dict, List[Dict]]]:
    

     return {
        
        "actionticket": [self.from_entity(entity="action_ticket",intent=["inform_ticket"])]
      }

    def submit(
    self,
    dispatcher: CollectingDispatcher,
    tracker: Tracker,
    domain: Dict[Text, Any],
        ) -> List[Dict]:
        
        return []

class ActionJiraId(Action):

     def name(self) -> Text:
         return "action_jira"

     def run(self, dispatcher: CollectingDispatcher,
             tracker: Tracker,
             domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        import requests

        jira_id=tracker.get_slot('jira_id')

        jira_API=config_resp['JIRA_API_ENDPOINT']
        jira_key=config_resp['JIRA_APIKEY']
        url = jira_API+"{}".format(jira_id) 

        headers = {
               'authorization': jira_key
    
                }
        try:
           response = requests.request("GET", url, headers=headers,verify = cert_root)

           r=response.json()
           #print(r)
           i=0
           res=""
           if response.status_code==200:
           
            if r['fields']['issuetype']['name']!=None and len(r['fields']['issuetype']['name']):res=res+("<b>IssueType</b>:{}<br>".format(r['fields']['issuetype']['name']))
            if r['fields']['summary']!=None and len(r['fields']['summary']):res=res+("<b>Summary</b>: {}<br>".format((r['fields']['summary'])))
            if r['fields']['assignee']['displayName']!=None and len(r['fields']['assignee']['displayName']):res=res+("<b>Assignee:</b> {}<br>".format(r['fields']['assignee']['displayName']))
            if r['fields']['reporter']['displayName']!=None and len(r['fields']['reporter']['displayName']):res=res+("<b>Reporter:</b>{}<br>".format(r['fields']['reporter']['displayName']))
            if r['fields']['status']['name']!=None and len(r['fields']['status']['name']):res=res+("<b>Status:</b>{}<br>".format((r['fields']['status']['name'])))
            if r['fields']['duedate']!=None and len(r['fields']['duedate']):res=res+("<b>Duedate:</b>{}<br>".format((r['fields']['duedate'])))
            if r['fields']['fixVersions']!=None and len(r['fields']['fixVersions'])!=0:res=res+("<b>FixVersions:</b>{}<br>".format((r['fields']['fixVersions'][0]['name'])))
            res=res+("<b>Comments:</b><br>")
            while i>=0 and i<len(r['fields']['comment']['comments']):
             if i==3:
               break;
             res=res+("<b>{}</b>".format(r['fields']['comment']['comments'][i]['updateAuthor']['displayName'])+":<br>"+"{}<br>".format(r['fields']['comment']['comments'][i]['body']))
             i+=1

            dispatcher.utter_message(res)
        except Exception as e:
          dispatcher.utter_message('Something went wrong Please try Again')
          
        return [AllSlotsReset()]

class ActionRPA_submenu(Action):

     def name(self) -> Text:
         return "action_rpa_menu"  

     def run(self, dispatcher: CollectingDispatcher,
             tracker: Tracker,
             domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        
        rpa_application=tracker.get_slot('rpa_portal').lower()

        if rpa_application=='broker':
          dispatcher.utter_message(template="utter_ask_rpa_broker")
          return []
        elif rpa_application=='member':
          dispatcher.utter_message(template="utter_ask_rpa_member")
          return []         
        elif rpa_application=='employer':
          dispatcher.utter_message(template="utter_ask_rpa_employer")
          return []
        elif rpa_application=='shopper':
          dispatcher.utter_message(template="utter_Shopper_options")
          return []
        
        else:
          dispatcher.utter_message("Something went wrong, Please try again")

class ActionRPABot(Action):

     def name(self) -> Text:
         return "action_rpa_bot"

     def run(self, dispatcher: CollectingDispatcher,
             tracker: Tracker,
             domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        import requests
        import json
        import time
        
        rpa_application=tracker.get_slot('rpa_portal')
        screensToValidate=tracker.get_slot('screensToValidate')
        ApplicationName=tracker.get_slot('ApplicationName')
        domainID= tracker.sender_id
        if rpa_application.lower()=='shopper' or rpa_application.lower()=="employer" or rpa_application.lower()=="broker":
         c={'transaction':'All','emailRecepient':domainID,'applicationName':ApplicationName}
        else:
         c={'screensToValidate':'All','domainID':domainID,'region':'All'}
        c=json.dumps(c)
        rpa_application=rpa_application.lower()
        stack_auth_key=config_resp['STACKSTORM_AUTHTOKEN_KEY']
        url = config_resp['STACKSTORM_AUTHTOKEN_API']
        headers = { 'Authorization': stack_auth_key}
        if rpa_application=='broker':
          rpa_release_key = config_resp['RPA_BROKER_KEY']
        elif rpa_application=='member':
          rpa_release_key = config_resp['RPA_MEMBER_KEY']
        elif rpa_application=='shopper':
          rpa_release_key = config_resp['RPA_SHOPPER_KEY']          
        elif rpa_application=='employer':
          rpa_release_key = config_resp['RPA_EMPLOYER_KEY']

        try:
         payload={}
         response = requests.request("POST", url, headers=headers, data = payload,verify = cert)
         #print(response.status_code)
         if response.status_code==201:
          token=(response.json()['token'])
         print(token)
         base_url=config_resp['STACKSTORM_EXECUTION_API']
         headers={'X-Auth-Token':token,'content-type':'application/json'}
         #print("imhereeee")
         data = {
         "action": "rpa.StartRPABot",
         "parameters": {
         "ReleaseKey":rpa_release_key,
         "RobotIds": [
          config_resp['RPA_ROBOT_ID']
         ],
         "InputArguments":c
           }
         }
         data=json.dumps(data)
         print(data)
         # sending post request and saving response as response object 
         r = requests.post(url = base_url, data = data,headers=headers, verify = cert)
         print(r.json())
         unique_id=r.json()['id']
         thresold=0
         print(unique_id)
         apiurl=base_url+'/'+'{}'.format(unique_id)
         while thresold<=60:
            response=requests.get(apiurl,verify = cert,headers=headers)
            if response.json()['status'] in [ "succeeded"]:
                    if '201' in (response.json()['result']['output']['stdout']):
                        dispatcher.utter_message("The validation has been started and an email will be sent with report post validation.")
                    if '409' in (response.json()['result']['output']['stdout']):
                        dispatcher.utter_message("The bots are busy,Please try after sometime for portal validation")
                    break 
            time.sleep(2)
            thresold=thresold+2
         if thresold>=60:
          dispatcher.utter_message("Something went wrong ,please try again")
        except Exception as e:
          dispatcher.utter_message("Something went wrong,Please try again")   
        return [AllSlotsReset()]


class ActionDefaultFallback(Action):
    def name(self) -> Text:
        return "action_default_fallback"

    def run(
        self,
        dispatcher: CollectingDispatcher,
        tracker: Tracker,
        domain: Dict[Text, Any],
    ) -> List[EventType]:

       
        dispatcher.utter_message(template="utter_default")
        return [UserUtteranceReverted()]

class ActioncloseCtask(Action):
    def name(self) -> Text:
        return "action_close_ctask"

    def run(
        self,
        dispatcher: CollectingDispatcher,
        tracker: Tracker,
        domain: Dict[Text, Any],
    ) -> List[EventType]:
     try:
      CtaskNum=tracker.get_slot("change_ticket")
      sctask_auth_key=config_resp['SCTASK_APIKEY']
      #CtaskNum="CTASK1315019"
      url  = config_resp['CHANGE_TASK_ENDPOINT']+"number={}".format(CtaskNum)
      payload={}
      headers = {'Authorization': sctask_auth_key}
      response = requests.request("GET", url, headers=headers, data=payload,verify=False)
      sysid=(response.json()['result'][0]['sys_id'])
      print(sysid)
      url = config_resp['CHANGE_TASK_ENDPOINT_CLOSE']+"/{}".format(sysid)
      work_notes=tracker.get_slot("work_notes")
      close_notes=tracker.get_slot("close_notes")
      payload = json.dumps({
          "number": "{}".format(CtaskNum),
          "state": "-7",
          "work_notes": "{} has closed this using ChatBot with below notes :{}".format(tracker.sender_id,work_notes),
          "close_notes": "{}".format(close_notes)
            })
      print(payload)
      headers = {
        'Content-Type': 'application/json',
        'Authorization': sctask_auth_key}
      response = requests.request("PUT", url, headers=headers, data=payload)
      print(response.json())
      dispatcher.utter_message("The Change task is closed for  {}".format(CtaskNum))
      return [AllSlotsReset()]
     except Exception as e:
       dispatcher.utter_message("The Change task closure failed,Please try again")
       return [AllSlotsReset()]

class ActionCustomfallback(Action):
    """Asks for an affirmation of the intent if NLU threshold is not met."""

    def name(self) -> Text:
        return "action_custom_fallback"

    def run(
        self,
        dispatcher: CollectingDispatcher,
        tracker: Tracker,
        domain: Dict[Text, Any],
    ) -> List[EventType]:

        
        searchterm = tracker.latest_message.get('text')
        message_title = (
            "Sorry, I'm not sure I've understood " "you correctly ðŸ¤” try searching in..."
            )
        buttons = []
        buttons.append({"title": 'Confluence', "payload": "/Confluence"})
        buttons.append({"title": "Something else", "payload": "/trigger_rephrase"})
        dispatcher.utter_message(text=message_title, buttons=buttons)
        return [SlotSet('searchterm', searchterm)]

class ActionConfXwiki(Action):

     def name(self) -> Text:
         return "action_confluence_invoke"

     def run(self, dispatcher: CollectingDispatcher,
             tracker: Tracker,
             domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        
        import requests
        import xmltodict
        import json
        import re
        usr_input=tracker.get_slot('searchterm')
        #print(usr_input)
        def similarity(usr_input,wiki_input):
         from nltk.corpus import stopwords 
         from nltk.tokenize import word_tokenize 
        # X = input("Enter first string: ").lower() 
        # Y = input("Enter second string: ").lower() 
         X =usr_input.lower()
         Y =wiki_input.lower()
         # tokenization 
         X_list = word_tokenize(X)  
         Y_list = word_tokenize(Y) 
         # sw contains the list of stopwords 
         sw = stopwords.words('english')  
         l1 =[];l2 =[] 
         # remove stop words from string 
         X_set = {w for w in X_list if not w in sw}  
         Y_set = {w for w in Y_list if not w in sw} 
         # form a set containing keywords of both strings  
         rvector = X_set.union(Y_set)  
         for w in rvector: 
             if w in X_set: l1.append(1) # create a vector 
             else: l1.append(0) 
             if w in Y_set: l2.append(1) 
             else: l2.append(0) 
         c = 0
         # cosine formula  
         for i in range(len(rvector)): 
                c+= l1[i]*l2[i] 
         if float((sum(l1)*sum(l2))**0.5)!=0:       
           cosine = c / float((sum(l1)*sum(l2))**0.5) 
         else:
           cosine=0 
         if cosine>0.0:
             pass
          #print("The score of match",cosine)
         return cosine


        def confluence(usr_input):
         import requests
         headers = {
            'authorization': config_resp['CONFLUENCE_KEY']
            }
         con_url=config_resp['CONFLUENCE_PLAIN_API']
         con_rest_api=config_resp['CONFLUENCE_API']
         try:
          response = requests.get(con_rest_api+'"{}"'.format(usr_input),verify = cert_root, headers=headers)
          #print(response)
      
          # If the HTTP GET request can be served
          if response.status_code == 200:
              total={}
              #print("Searching confluence...")   
              r_json=response.json()
             #print(r_json)
              if 'results' in r_json:
               for each in r_json['results']:
       
                if 'content' in each:
                 title = each['content']['title']
                 #id = each['content']['id']
                 link=each['content']['_links']['webui']
                 shortDesc=each['excerpt']
                 shortDesc=re.sub(r'@@@hl@@@','<b>',shortDesc)
                 shortDesc=re.sub(r'@@@endhl@@@','</b>',shortDesc)
                 shortDesc=re.sub(r'&#39;','',shortDesc)
                 shortDesc=re.sub(r'\n','',shortDesc)
                 score=similarity(usr_input,shortDesc)
                 #print(score)
                if score>=0.0:
                 total[title+'::'+con_url+link+'::'+shortDesc]=score
       #print(total)
             #print(title)
             #print(con_url+link+'\n') 
              a = sorted(total.items(), key=lambda x: x[1],reverse=True)
              b=dict(a)
              #print(b.keys())
              if len(b.keys())>0:
                dispatcher.utter_message("Fetching top matching results found in Confluence ")
              else:
                dispatcher.utter_message("There are no matching results found in Confluence ")
              res=''
              for each in b.keys():
              #dispatcher.utter_message('**'+each.split("::")[0]+'**')
               res=res+'<a href="{}" target="_blank"><b>{}</b></a>{}<br>'.format(each.split("::")[1],each.split("::")[0],each.split("::")[2])
              dispatcher.utter_message(res)
               #dispatcher.utter_message(each.split("::")[2])
         except Exception as e:
            dispatcher.utter_message("Oops couldn't find matching pages,Please try again")
            #print(e)
        #print(tracker.latest_message.get('text'))  
        dispatcher.utter_message('Searching...')
        if tracker.get_slot('confluence')=='confluence':  
          confluence(usr_input)
        else:
          confluence(usr_input)
        return[AllSlotsReset()]
class Actioncomments(Action):
   def name(self):
       return "action_searchterm"

 

   def run(self, dispatcher, tracker, domain):
 
       searchterm = tracker.latest_message.get('text')
       #dispatcher.utter_message(comment)
       return [SlotSet('searchterm', searchterm)]    

class Actionsearchformconf(FormAction):
    def name(self) -> Text:
        return "search_form"
    @staticmethod
    def required_slots(tracker: Tracker)-> List[Text]:
        return{"searchterm"}
    def slot_mappings(self) -> Dict[Text, Union[Dict, List[Dict]]]:
    

     return {
        
        "searchterm": [self.from_text()]
      }

    def submit(
    self,
    dispatcher: CollectingDispatcher,
    tracker: Tracker,
    domain: Dict[Text, Any],
        ) -> List[Dict]:
        
        return []

class Actionsearchformconf(FormAction):
    def name(self) -> Text:
        return "feedback_form"
    @staticmethod
    def required_slots(tracker: Tracker)-> List[Text]:
        return{"feedback_txt"}
    def slot_mappings(self) -> Dict[Text, Union[Dict, List[Dict]]]:
    

     return {
        
        "feedback_txt": [self.from_text()]
      }

    def submit(
    self,
    dispatcher: CollectingDispatcher,
    tracker: Tracker,
    domain: Dict[Text, Any],
        ) -> List[Dict]:
        
        return []

class Actionsearchformecms(FormAction):
    def name(self) -> Text:
        return "ecms_form"
    @staticmethod
    def required_slots(tracker: Tracker)-> List[Text]:
        return{"cert_name"}
    def slot_mappings(self) -> Dict[Text, Union[Dict, List[Dict]]]:
    

     return {
        
        "cert_name": [self.from_text()]
      }

    def submit(
    self,
    dispatcher: CollectingDispatcher,
    tracker: Tracker,
    domain: Dict[Text, Any],
        ) -> List[Dict]:
        dispatcher.utter_message("Fetching certificate details...!")
        return []
class Actionsearchformdom1(FormAction):
    def name(self) -> Text:
        return "domainid_form"
    @staticmethod
    def required_slots(tracker: Tracker)-> List[Text]:
        return{"domainid"}
    def slot_mappings(self) -> Dict[Text, Union[Dict, List[Dict]]]:
    

     return {
        
        "domainid": [self.from_text()]
      }

    def submit(
    self,
    dispatcher: CollectingDispatcher,
    tracker: Tracker,
    domain: Dict[Text, Any],
        ) -> List[Dict]:
        
        return []

class Actionsearchformdom(FormAction):
    def name(self) -> Text:
        return "splunkuri_form"
    @staticmethod
    def required_slots(tracker: Tracker)-> List[Text]:
        return{"splunk_uri"}
    def slot_mappings(self) -> Dict[Text, Union[Dict, List[Dict]]]:
    

     return {
        
        "splunk_uri": [self.from_text()]
      }

    def submit(
    self,
    dispatcher: CollectingDispatcher,
    tracker: Tracker,
    domain: Dict[Text, Any],
        ) -> List[Dict]:
        
        return []

class ActionECMS(Action):

     def name(self) -> Text:
         return "action_ecms"

     def run(self, dispatcher: CollectingDispatcher,
             tracker: Tracker,
             domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        import requests
        import json
        cert_name=tracker.get_slot("cert_name")
        app_name=tracker.get_slot("cert_category")
        cert_url=config_resp['ECMS_API_ENDPOINT']
        try:
          url = cert_url+"getECMSCertDetailsAPI.htm?certName={}&appName={}".format(cert_name,app_name)
          response = requests.request("GET", url,verify = cert_root)
          r=response.json()
          #print(r,url)
          res=""
          if response.status_code==200:
            if r!='No Data Found':
                for each in r:
                    if True:
                        #dispatcher.utter_message("**Serial No:**{} \n **Domain Name:**{} \n**Components:**{}\n **Environment:**{}\n **Validity Start Date:**{}\n **Validity End Date:**{}\n\n".format(each['serialNo'],each['domainName'],each['components'],each['environment'],each['valStartDt'],each['valEndDt']))
                        if 'serialNo' in each:res=res+("<b>Serial No:</b>{}<br>".format(each['serialNo']))
                        if 'domainName' in each:res=res+("<b>Domain Name:</b>{}<br>".format(each['domainName']))
                        if 'components' in each:res=res+("<b>Components:</b>{}<br>".format(each['components']))
                        if 'environment'in each:res=res+("<b>Environment:</b>{}<br>".format(each['environment']))
                        if 'valStartDt' in each:res=res+("<b>Validity Start Date:</b>{}<br>".format(each['valStartDt']))
                        if 'valEndDt' in each:res=res+("<b>Validity End Date:</b>{}<br><br>".format(each['valEndDt']))
                        
                    elif app_name.lower()=='webapps':
                        #dispatcher.utter_message("**Serial No:**{}\n**Domain Name:**{}\n**Environment:**{}\n**Validity Start Date:**{}\n**Validity End Date:**{}\n\n".format(each['serialNo'],each['domainName'],each['environment'],each['valStartDt'],each['valEndDt']))
                        if each['serialNo']!=None and len(each['serialNo']):res=res+("<b>Serial No:</b>{}<br>".format(each['serialNo']))
                        if each['domainName']!=None and len(each['domainName']):res=res+("<b>Domain Name:</b>{}<br>".format(each['domainName']))
                        if each['environment']!=None and len(each['environment']):res=res+("<b>Environment:</b>{}<br>".format(each['environment']))
                        if each['valStartDt']!=None and len(each['valStartDt']):res=res+("<b>Validity Start Date:</b>{}<br>".format(each['valStartDt']))
                        if each['valEndDt']!=None and len(each['valEndDt']):res=res+("<b>Validity End Date:</b>{}<br><br>".format(each['valEndDt']))
                dispatcher.utter_message(res)    
            else:       
                dispatcher.utter_message("No Data Found")
          else:
            dispatcher.utter_message("Error retrieving Data please try again") 
        except Exception as e:
            dispatcher.utter_message("Something went wrong,Please try again")
            
        return [AllSlotsReset()]
    
class actionITVS(Action):

    def name(self) -> Text:
        return "action_itvs" 

    def run(self, dispatcher: CollectingDispatcher,
            tracker: Tracker,
            domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
      
      import requests 

      apiURL = config_resp['ITVS_URL']
      #apiURL = 'https://oneview-dev.anthem.com/DigitalAsset/getChangeSearchResult'
      itvs_search_cat = tracker.get_slot('itvs_search_cat')
      itvs_proje_name = tracker.get_slot('itvs_proje_name')
      itvs_search_txt = tracker.get_slot('itvs_search_txt') 
      itvs_server = tracker.get_slot('itvs_server')

      if itvs_search_cat == 'itvs_chg_no':
          apiurl = apiURL +'?projectName={}&searchCategory=Change%20No&searchText={}'.format(itvs_proje_name,itvs_search_txt)
          print(apiurl)
          response=requests.get(apiurl,verify = cert_root)
          res=""
          try:
              res=res+("<b>Change No :</b> {}<br>".format((response.json())[0]['changeNo']))
              res=res+("<b>Change Des:</b> {}<br>".format((response.json())[0]['shortDescription']))
              res=res+("<b>Environ is:</b> {}<br>".format((response.json())[0]['environment']))
              res=res+("<b>Status    :</b> {}<br>".format((response.json())[0]['status']))
              res=res+("<b>Start Date:</b> {}<br>".format((response.json())[0]['startTime']))
              res=res+("<b>End Date  :</b> {}<br>".format((response.json())[0]['endTime']))
              dispatcher.utter_message(res)
          except Exception as e:
            if 'expecting value' in str(e).lower():
               dispatcher.utter_message('Error: Incorrect api URL')
            elif 'out of range' in str(e).lower():
                dispatcher.utter_message('Error: No results for given values')
            elif 'SSLError' in str(e).lower():
                dispatcher.utter_message('Error: SSL certificate issue occured')
            else:
                dispatcher.utter_message('Error: Invalid Input')
      
      elif itvs_search_cat == 'itvs_server_nm':
          itvs_start_dt = tracker.get_slot('itvs_st_dt')
          itvs_end_dt = tracker.get_slot('itvs_en_dt')

          apiurl = apiURL +'?projectName={}&dateRange={} 00:00 - {} 23:59&searchCategory=Server%20Name&searchText={}'.format(itvs_proje_name,itvs_start_dt,itvs_end_dt,itvs_search_txt)

          print(apiurl)
          response=requests.get(apiurl,verify = cert_root)
          res=""
          try:
            for item in range(0,len(response.json())):
               res=res+("<b>Change No :</b> {}<br>".format((response.json())[item]['changeNo']))
               res=res+("<b>Change Des:</b> {}<br>".format((response.json())[item]['shortDescription']))
               res=res+("<b>Environ is:</b> {}<br>".format((response.json())[item]['environment']))
               res=res+("<b>Status    :</b> {}<br>".format((response.json())[item]['status']))
               res=res+("<b>Start Date:</b> {}<br>".format((response.json())[item]['startTime']))
               res=res+("<b>End Date  :</b> {}<br>".format((response.json())[item]['endTime']))
               dispatcher.utter_message(res)
               res=""
          except Exception as e:
             if 'expecting value' in str(e).lower():
                dispatcher.utter_message('Error: Incorrect api URL')
             elif 'out of range' in str(e).lower():
                dispatcher.utter_message('Error: No results for given values')
             elif 'SSLError' in str(e).lower():
                dispatcher.utter_message('Error: SSL certificate issue occured')
             else:
                dispatcher.utter_message('Error: Invalid Input') 

      elif itvs_search_cat == 'itvs_App_nm':
          itvs_start_dt = tracker.get_slot('itvs_st_dt')
          itvs_end_dt = tracker.get_slot('itvs_en_dt') 

          apiurl = apiURL +'?projectName={}&dateRange={} 00:00 - {} 23:59&searchCategory=Application%20Name&searchText={}'.format(itvs_proje_name,itvs_start_dt,itvs_end_dt,itvs_search_txt)
          print(apiurl)
          response=requests.get(apiurl,verify = cert_root)
          res=""
          try:
            for item in range(0,len(response.json())):
              res=res+("<b>Change No :</b> {}<br>".format((response.json())[item]['changeNo']))
              res=res+("<b>Change Des:</b> {}<br>".format((response.json())[item]['shortDescription']))
              res=res+("<b>Environ is:</b> {}<br>".format((response.json())[item]['environment']))
              res=res+("<b>Status    :</b> {}<br>".format((response.json())[item]['status']))
              res=res+("<b>Start Date:</b> {}<br>".format((response.json())[item]['startTime']))
              res=res+("<b>End Date  :</b> {}<br>".format((response.json())[item]['endTime']))
              dispatcher.utter_message(res)
              res=""
          except Exception as e:
            if 'expecting value' in str(e).lower():
              dispatcher.utter_message('Error: Incorrect api URL')
            elif 'out of range' in str(e).lower():
              dispatcher.utter_message('Error: No results for given values')
            elif 'SSLError' in str(e).lower():
              dispatcher.utter_message('Error: SSL certificate issue occured')
            else:
              dispatcher.utter_message('Error: Invalid Input') 

      else:
          if str(itvs_server) != 'None':
            itvs_start_dt = tracker.get_slot('itvs_st_dt')
            itvs_end_dt = tracker.get_slot('itvs_en_dt')        
            apiurl = apiURL +'?projectName=Portal&dateRange={} 00:00 - {} 23:59&searchCategory=Server%20Name&searchText={}'.format(itvs_start_dt,itvs_end_dt,itvs_server)
          else:
            apiurl = apiURL +'?projectName=Portal&searchCategory=Change%20No&searchText={}'.format(tracker.get_slot('itvs_id'))

          print(apiurl)
          response=requests.get(apiurl,verify = cert_root)
          res=""
          try:
              res=res+("<b>Change No :</b> {}<br>".format((response.json())[0]['changeNo']))
              res=res+("<b>Change Des:</b> {}<br>".format((response.json())[0]['shortDescription']))
              res=res+("<b>Environ is:</b> {}<br>".format((response.json())[0]['environment']))
              res=res+("<b>Status    :</b> {}<br>".format((response.json())[0]['status']))
              res=res+("<b>Start Date:</b> {}<br>".format((response.json())[0]['startTime']))
              res=res+("<b>End Date  :</b> {}<br>".format((response.json())[0]['endTime']))
              dispatcher.utter_message(res)
          except Exception as e:
            if 'expecting value' in str(e).lower():
               dispatcher.utter_message('Error: Incorrect api URL')
            elif 'out of range' in str(e).lower():
                dispatcher.utter_message('Error: No results for given values')
            elif 'SSLError' in str(e).lower():
                dispatcher.utter_message('Error: SSL certificate issue occured')
            else:
                dispatcher.utter_message('Error: Invalid Input')

      return [AllSlotsReset()]
 

class Action_plain_txt_form(FormAction):
    def name(self) -> Text:
        return "Action_itvs_src_txt_form"
    @staticmethod
    def required_slots(tracker: Tracker)-> List[Text]:
        return{"itvs_search_txt"}
    def slot_mappings(self) -> Dict[Text, Union[Dict, List[Dict]]]:
    

     return {
        
        "itvs_search_txt": [self.from_text()]
      }

    def submit(
    self,
    dispatcher: CollectingDispatcher,
    tracker: Tracker,
    domain: Dict[Text, Any],
        ) -> List[Dict]:
        
        return []

class Action_itvs_option_text(Action):
   def name(self):
       return "Action_itvs_option_text" 
 

   def run(self, dispatcher, tracker, domain):
       itvs_search_cat = tracker.get_slot('itvs_search_cat')
       
       if itvs_search_cat == 'itvs_chg_no':
        dispatcher.utter_message('Please provide the Ticket No?')
       if itvs_search_cat == 'itvs_server_nm':
        dispatcher.utter_message('Please provide Server Name?')
       if itvs_search_cat == 'itvs_App_nm':
        dispatcher.utter_message('Please provide Application Name?')
       return [] 

class Action_itvs_date_form(Action):

   def name(self):
       return "Action_itvs_date_form"

   def run(self, dispatcher, tracker, domain):
    itvs_dt = tracker.get_slot('itvs_dt')
    if itvs_dt == None:
      return [SlotSet('itvs_st_dt', tracker.latest_message.get('text')),SlotSet('itvs_dt', 'stdt')]
    elif itvs_dt == 'stdt':
      return [SlotSet('itvs_en_dt', tracker.latest_message.get('text'))]
    else:
      dispatcher.utter_message('Invalid')
    return []

class Action_Splunk_time_option(Action):
   def name(self):
       return "Action_Splunk_opt1" 
 

   def run(self, dispatcher, tracker, domain):
       import time
       time_option = tracker.get_slot('splunk_time_option')
       
       if time_option == 'preset':
        dispatcher.utter_message(template="utter_splunk_time_options")
        return[]
       if time_option == 'custom':
        message={"payload":"dateTimePicker"}
        dispatcher.utter_message(text="Please select datetime range:",json_message=message)
       return [] 
class Action_ctask_time_option(Action):
   def name(self):
       return "action_ctask_time" 
 

   def run(self, dispatcher, tracker, domain):
        message={"payload":"ctaskdateTimePicker"}
        dispatcher.utter_message(text="Please select datetime range:",json_message=message)
        return [] 

class actionticket(Action):
    
    def name(self) -> Text:
         return "action_splunk_options"
    def run(self, dispatcher: CollectingDispatcher,
            tracker: Tracker,
            domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:

          buttons = []

          message_title = "Kindly select splunk usecase:"

          buttons.append(
                    {"title": 'API/service Issue', "payload": '/splunk_status{"splunk_Category": "sp_cat_issue"}'}
                )

          buttons.append(
                    {"title": '500% Error', "payload": '/splunk_status{"splunk_Category": "500_error"}'}
                )

          buttons.append(
                    {"title": 'Top 5 errors', "payload": '/splunk_status{"splunk_Category": "top_5_errors"}'}
                )
          buttons.append(
                    {"title": 'Performance of an API', "payload": '/splunk_status{"splunk_Category": "perf_api"}'}
                )

          buttons.append(
                    {"title": '10s & more response time', "payload": '/splunk_status{"splunk_Category": "10s_more"}'}
                )

          buttons.append(
                    {"title": 'Hourly Response Trend', "payload": '/splunk_status{"splunk_Category": "sp_cat_trend"}'}
                )

          buttons.append(
                    {"title": 'API response time', "payload": '/splunk_status{"splunk_Category": "res_status"}'}
                )

          buttons.append(
                    {"title": 'Fetch Consumers', "payload": '/splunk_status1{"splunk_Category": "fetch_consumers"}'}
                )

          buttons.append(
                    {"title": 'Target Host', "payload": '/splunk_status1{"splunk_Category": "target_host"}'}
                )

          dispatcher.utter_message(text=message_title, buttons=buttons)

          return[]


class action_Splunk(Action):

    def name(self) -> Text:
        return "action_splunk"

    def run(self, dispatcher: CollectingDispatcher,
            tracker: Tracker,
            domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        import requests
        import json
        import time
        import datetime
        from tabulate import tabulate
        import webbrowser
        from datetime import datetime
        import csv 
        import base64

        splunk_option=tracker.get_slot('splunk_Category')
        stack_auth_key= config_resp['STACK_SPLUNK_KEY']
        splunk_api =  config_resp['STACK_SPLUNK_URL_TOKEN']
        headers = { 'Authorization': stack_auth_key}
        splunk_time=None
        splunk_time1=None
        time.sleep(2)        

        splunk_uri=  tracker.get_slot('splunk_uri')
        # if tracker.get_slot('datetime') is not None:
        #   splunk_time1 = tracker.get_slot('datetime')
        # elif tracker.get_slot('datetimerange') is not None:
        #   splunk_time1 = tracker.get_slot('datetimerange')
        # elif tracker.get_slot('daterange') is not None:
        #   splunk_time1 = tracker.get_slot('daterange')
        # elif tracker.get_slot('date') is not None:
        #   splunk_time1 = tracker.get_slot('date')
        splunk_time1= tracker.get_slot('splunk_time1')
            
        if splunk_time1 is None:
          splunk_time= tracker.get_slot('splunk_time')
          splunk_time1='now'
        else:
          splunk_time=tracker.get_slot('splunk_time')
          splunk_time1=tracker.get_slot('splunk_time1')
          # if "start_date" in splunk_time1 or "start_time" in splunk_time1:
          #   if "start_time" in splunk_time1:
          #     starttime=splunk_time1["start_time"]
          #     splunk_time2 = datetime.fromisoformat(starttime)
          #     splunk_time = datetime.timestamp(splunk_time2)
          #     splunk_time = str(splunk_time)
          #   else:
          #     startdate=splunk_time1["start_date"]
          #     splunk_time2 = datetime.fromisoformat(startdate)
          #     splunk_time = datetime.timestamp(splunk_time2)
          #     splunk_time = str(splunk_time)
          # else:
          #     splunk_time2 = datetime.fromisoformat(splunk_time1)
          #     splunk_time = datetime.timestamp(splunk_time2)
          #     splunk_time = str(splunk_time)
          # if "end_date" in splunk_time1 or "end_time" in splunk_time1:
          #   if "end_time" in splunk_time1:
          #     endtime=splunk_time1["end_time"]
          #     splunk_time2 = datetime.fromisoformat(endtime)
          #     splunk_time3 = datetime.timestamp(splunk_time2)
          #     splunk_time3 = str(splunk_time)
          #   else:
          #     enddate=splunk_time1["end_date"]
          #     splunk_time2 = datetime.fromisoformat(enddate)
          #     splunk_time3 = datetime.timestamp(splunk_time2)
          #     splunk_time3 = str(splunk_time)
          # else:
          #     splunk_time2 = datetime.fromisoformat(splunk_time1)
          #     splunk_time3 = datetime.timestamp(splunk_time2)
          #     splunk_time3 = str(splunk_time)

        if splunk_option == 'sp_cat_issue':
            


            payload={}
            response = requests.request("POST", splunk_api, headers=headers, data = payload,verify = cert)

            try:
              if response.status_code==201:
                token=(response.json()['token'])
                base_url= config_resp['STACK_SPLUNK_URL_EXEC'] 
                headers={'X-Auth-Token':token,'content-type':'application/json'}
                splunkurl= config_resp['STACK_SPLUNK_URL'] 
                SearchQuery= {'search': 'search index=apigee_prod source="tcp:9993" URI=*'+ splunk_uri +'* NOT Status=200 | rex field=URI "(?<API>(^[^?]+))"  | rex field=API mode=sed "s/[0-9A-Z-~_]{1,50}//g"| stats count by API Status |sort count desc', 'earliest_time': '' + splunk_time + '', 'latest_time': '' + splunk_time1 + '', 'output_mode': 'json', 'ttl': '100000'}
                data = {
                "action": "rpa.runQuery",
                "parameters": {
                "data":SearchQuery,
                "url": splunkurl,
                "threshodLimit": 180,
                "Authorization": config_resp['STACK_SPLUNK_CALL_KEY']  
                   }
                 }
                 
                data=json.dumps(data)
                r = requests.post(url = base_url, data = data,headers=headers, verify = cert)
                unique_id=r.json()['id']
                thresold=0
                
                responserul= base_url+"/{}".format(unique_id)
                time.sleep(2) 

                thresold=0

                while thresold<=60:
                  Headers=[]
                  formated_str = ""
                  time.sleep(2)
                  response=requests.get(responserul,verify = cert,headers=headers)

                  if response.json().get('status') == "succeeded":
                    for item in response.json()['result']['result']:
                      Headers=item.keys()
                    break
                  elif response.json().get('status') == "failed":
                    dispatcher.utter_message('Currently it is taking longer time to fetch the report. Please try again by giving complete uri or lesser time.')
                    return[AllSlotsReset()]
                    break

                if len(response.json()['result']['result']) == 0:
                  dispatcher.utter_message('There is no report fetched for the search criteria')
                  return[AllSlotsReset()]

                Headers=list(Headers)
                Headers.remove("API")
                Headers.insert(0,"API")

                if response.json().get('status') == "succeeded":
                  t = time.localtime()
                  timestamp = time.strftime('%m-%d-%Y_%H%M%S', t)
                  splunkfile=("SplunkReport_"+timestamp+".csv")
                  pj = open(splunkfile,"w",newline="")
                  pjcsv=csv.writer(pj)
                  pjcsv.writerow(Headers)

                  for each in response.json().get('result').get("result"):
                    eachRow=[]
                    for eachH in Headers:
                      eachRow.append(each.get(eachH))
                    pjcsv.writerow(eachRow)
                  pj.close()
                  with open(splunkfile) as splunkf:
                    Content = splunkf.read()
                  data = open(splunkfile, "rb").read()
                  encoded = (base64.b64encode(data))
                  message={"payload":"Splunkdata","data":encoded}
                  dispatcher.utter_message(text="Please click here to download report:",json_message=message)
                  os.remove(splunkfile)

            except Exception as e:
              if 'expecting value' in str(e).lower():
                dispatcher.utter_message('Error: Incorrect api URL')
              elif 'out of range' in str(e).lower():
                dispatcher.utter_message('Error: No results for given values')
              elif 'SSLError' in str(e).lower():
                dispatcher.utter_message('Error: SSL certificate issue occured')
              else:
                dispatcher.utter_message(e)
            return [AllSlotsReset()]

        elif splunk_option == '500_error':
            


            payload={}
            response = requests.request("POST", splunk_api, headers=headers, data = payload,verify = cert)
            
            try:
              if response.status_code==201:
                token=(response.json()['token'])
                base_url= config_resp['STACK_SPLUNK_URL_EXEC'] 
                headers={'X-Auth-Token':token,'content-type':'application/json'}
                splunkurl= config_resp['STACK_SPLUNK_URL'] 
                SearchQuery= {'search': 'search index=apigee_prod source="tcp:9993" URI=*'+splunk_uri +'* NOT Status=200 | rex field=URI "(?<API>(^[^?]+))"  | rex field=API mode=sed "s/[0-9A-Z-~_]{1,50}//g"| stats count as TotalCount count(eval(Status=500)) as Count500 by API| eval Perc500=round(Count500*100/TotalCount, 2)  | table API Count500 Perc500', 'earliest_time': '' + splunk_time + '', 'latest_time': '' + splunk_time1 + '', 'output_mode': 'json', 'ttl': '100000'}
                data = {
                "action": "rpa.runQuery",
                "parameters": {
                "data":SearchQuery,
                "url": splunkurl,
                "threshodLimit": 60,
                "Authorization": config_resp['STACK_SPLUNK_CALL_KEY']  
                   }
                 }
                 
                data=json.dumps(data)
                r = requests.post(url = base_url, data = data,headers=headers, verify = cert)
                unique_id=r.json()['id']
                thresold=0

                responserul= base_url+"/{}".format(unique_id)
                time.sleep(2) 

                thresold=0
                aggregated_resp={}

                while thresold<=60:
                  formated_str = ""
                  time.sleep(2)
                  response=requests.get(responserul,verify = cert,headers=headers)

                  if response.json().get('status') == "succeeded":
                    for item in response.json()['result']['result']:
                      Headers=item.keys()
                    break
                  elif response.json().get('status') == "failed":
                    dispatcher.utter_message('Currently it is taking longer time to fetch the report. Please try again by giving complete uri or lesser time.')
                    return[AllSlotsReset()]
                    break

                if len(response.json()['result']['result']) == 0:
                  dispatcher.utter_message('There is no report fetched for the search criteria')
                  return[AllSlotsReset()]

                Headers=list(Headers)
                Headers.remove("API")
                Headers.insert(0,"API")
                if response.json().get('status') == "succeeded":
                  t = time.localtime()
                  timestamp = time.strftime('%m-%d-%Y_%H%M%S', t)
                  splunkfile=("SplunkReport_"+timestamp+".csv")
                  pj = open(splunkfile,"w",newline="")
                  pjcsv=csv.writer(pj)
                  pjcsv.writerow(Headers)

                  for each in response.json().get('result').get("result"):
                    eachRow=[]
                    for eachH in Headers:
                      eachRow.append(each.get(eachH))
                    pjcsv.writerow(eachRow)
                  pj.close()
                  with open(splunkfile) as splunkf:
                    Content = splunkf.read()
                  data = open(splunkfile, "rb").read()
                  encoded = (base64.b64encode(data))
                  message={"payload":"Splunkdata","data":encoded}
                  dispatcher.utter_message(text="Please click here to download report:",json_message=message)
                  os.remove(splunkfile)

            except Exception as e:
              if 'expecting value' in str(e).lower():
                dispatcher.utter_message('Error: Incorrect api URL')
              elif 'out of range' in str(e).lower():
                dispatcher.utter_message('Error: No results for given values')
              elif 'SSLError' in str(e).lower():
                dispatcher.utter_message('Error: SSL certificate issue occured')
              else:
                dispatcher.utter_message(e)
            return [AllSlotsReset()]

        elif splunk_option == 'top_5_errors':
            


            payload={}
            response = requests.request("POST", splunk_api, headers=headers, data = payload,verify = cert)
            
            try:
              if response.status_code==201:
                token=(response.json()['token'])
                base_url= config_resp['STACK_SPLUNK_URL_EXEC'] 
                headers={'X-Auth-Token':token,'content-type':'application/json'}
                splunkurl= config_resp['STACK_SPLUNK_URL'] 
                SearchQuery= {'search': 'search index=apigee_prod source="tcp:9993" URI=*'+splunk_uri +'* NOT Status=200 | rex field=URI "(?<API>(^[^?]+))"  | rex field=API mode=sed "s/[0-9A-Z-~_]{1,50}//g"| stats count by API Status ErrorMsg  | top limit=5 API Status ErrorMsg', 'earliest_time': '' + splunk_time + '', 'latest_time': '' + splunk_time1 + '', 'output_mode': 'json', 'ttl': '100000'}
                data = {
                "action": "rpa.runQuery",
                "parameters": {
                "data":SearchQuery,
                "url": splunkurl,
                "threshodLimit": 60,
                "Authorization": config_resp['STACK_SPLUNK_CALL_KEY']  
                   }
                 }
                 
                data=json.dumps(data)
                r = requests.post(url = base_url, data = data,headers=headers, verify = cert)
                unique_id=r.json()['id']
                thresold=0

                responserul= base_url+"/{}".format(unique_id)
                time.sleep(2) 

                thresold=0
                aggregated_resp={}

                while thresold<=60:
                  formated_str = ""
                  time.sleep(2)
                  response=requests.get(responserul,verify = cert,headers=headers)

                  if response.json().get('status') == "succeeded":
                    for item in response.json()['result']['result']:
                      Headers=item.keys()
                    break
                  elif response.json().get('status') == "failed":
                    dispatcher.utter_message('Currently it is taking longer time to fetch the report. Please try again by giving complete uri or lesser time.')
                    return[AllSlotsReset()]
                    break

                if len(response.json()['result']['result']) == 0:
                  dispatcher.utter_message('There is no report fetched for the search criteria')
                  return[AllSlotsReset()]

                Headers=list(Headers)
                Headers.remove("_tc")
                Headers.remove("API")
                Headers.insert(0,"API")
                Headers.remove("ErrorMsg")
                Headers.insert(2,"ErrorMsg")
                if response.json().get('status') == "succeeded":
                  t = time.localtime()
                  timestamp = time.strftime('%m-%d-%Y_%H%M%S', t)
                  splunkfile=("SplunkReport_"+timestamp+".csv")
                  pj = open(splunkfile,"w",newline="")
                  pjcsv=csv.writer(pj)
                  pjcsv.writerow(Headers)

                  for each in response.json().get('result').get("result"):
                    eachRow=[]
                    for eachH in Headers:
                      eachRow.append(each.get(eachH))
                    pjcsv.writerow(eachRow)
                  pj.close()
                  with open(splunkfile) as splunkf:
                    Content = splunkf.read()
                  data = open(splunkfile, "rb").read()
                  encoded = (base64.b64encode(data))
                  message={"payload":"Splunkdata","data":encoded}
                  dispatcher.utter_message(text="Please click here to download report:",json_message=message)
                  os.remove(splunkfile)

            except Exception as e:
              if 'expecting value' in str(e).lower():
                dispatcher.utter_message('Error: Incorrect api URL')
              elif 'out of range' in str(e).lower():
                dispatcher.utter_message('Error: No results for given values')
              elif 'SSLError' in str(e).lower():
                dispatcher.utter_message('Error: SSL certificate issue occured')
              else:
                dispatcher.utter_message(e)
            return [AllSlotsReset()]

        elif splunk_option == '10s_more': 
            


            payload={}
            response = requests.request("POST", splunk_api, headers=headers, data = payload,verify = cert)
            
            try:
              if response.status_code==201:
                token=(response.json()['token'])
                base_url= config_resp['STACK_SPLUNK_URL_EXEC'] 
                headers={'X-Auth-Token':token,'content-type':'application/json'}
                splunkurl= config_resp['STACK_SPLUNK_URL'] 
                SearchQuery= {'search': 'search index=apigee_prod source="tcp:9993" URI=*'+splunk_uri +'* NOT Status=200 | rex field=URI "(?<API>(^[^?]+))"  | rex field=API mode=sed "s/[0-9A-Z-~_]{1,50}//g"| eval TotalTime = TransactionSentEndtime - TransactionReceivedStartTime |stats max(TotalTime) as ResponseTime by API | where ResponseTime >10000 | sort ResponseTime desc', 'earliest_time': '' + splunk_time + '', 'latest_time': '' + splunk_time1 + '', 'output_mode': 'json', 'ttl': '100000'}
                data = {
                "action": "rpa.runQuery",
                "parameters": {
                "data":SearchQuery,
                "url": splunkurl,
                "threshodLimit": 60,
                "Authorization": config_resp['STACK_SPLUNK_CALL_KEY']  
                   }
                 }
                 
                data=json.dumps(data)
                r = requests.post(url = base_url, data = data,headers=headers, verify = cert)
                unique_id=r.json()['id']
                thresold=0

                responserul= base_url+"/{}".format(unique_id)
                time.sleep(2) 

                thresold=0
                aggregated_resp={}

                while thresold<=60:
                  formated_str = ""
                  time.sleep(2)
                  response=requests.get(responserul,verify = cert,headers=headers)

                  if response.json().get('status') == "succeeded":
                    for item in response.json()['result']['result']:
                      Headers=item.keys()
                    break
                  elif response.json().get('status') == "failed":
                    dispatcher.utter_message('Currently it is taking longer time to fetch the report. Please try again by giving complete uri or lesser time.')
                    return[AllSlotsReset()]
                    break

                if len(response.json()['result']['result']) == 0:
                  dispatcher.utter_message('There is no report fetched for the search criteria')
                  return[AllSlotsReset()]

                Headers=list(Headers)
                Headers.remove("API")
                Headers.insert(0,"API")
                if response.json().get('status') == "succeeded":
                  t = time.localtime()
                  timestamp = time.strftime('%m-%d-%Y_%H%M%S', t)
                  splunkfile=("SplunkReport_"+timestamp+".csv")
                  pj = open(splunkfile,"w",newline="")
                  pjcsv=csv.writer(pj)
                  pjcsv.writerow(Headers)

                  for each in response.json().get('result').get("result"):
                    eachRow=[]
                    for eachH in Headers:
                      eachRow.append(each.get(eachH))
                    pjcsv.writerow(eachRow)
                  pj.close()
                  with open(splunkfile) as splunkf:
                    Content = splunkf.read()
                  data = open(splunkfile, "rb").read()
                  encoded = (base64.b64encode(data))
                  message={"payload":"Splunkdata","data":encoded}
                  dispatcher.utter_message(text="Please click here to download report:",json_message=message)
                  os.remove(splunkfile)

            except Exception as e:
              if 'expecting value' in str(e).lower():
                dispatcher.utter_message('Error: Incorrect api URL')
              elif 'out of range' in str(e).lower():
                dispatcher.utter_message('Error: No results for given values')
              elif 'SSLError' in str(e).lower():
                dispatcher.utter_message('Error: SSL certificate issue occured')
              else:
                dispatcher.utter_message(e)
            return [AllSlotsReset()]

        elif splunk_option == 'sp_cat_trend':
            payload={}
            response = requests.request("POST", splunk_api, headers=headers, data = payload,verify = cert)
            try:
              if response.status_code==201:
                token=(response.json()['token'])
                base_url= config_resp['STACK_SPLUNK_URL_EXEC'] 
                headers={'X-Auth-Token':token,'content-type':'application/json'}
                splunkurl= config_resp['STACK_SPLUNK_URL'] 
                SearchQuery= {'search': 'search index=apigee_prod source="tcp:9993" URI=*'+splunk_uri +'* NOT Status=200 | rex field=URI "(?<API>(^[^?]+))"  | rex field=API mode=sed "s/[0-9A-Z-~_]{1,50}//g"| eval TotalTime = TransactionSentEndtime - TransactionReceivedStartTime |timechart span=1h max(TotalTime) by API', 'earliest_time': '' + splunk_time + '' , 'latest_time': '' + splunk_time1 + '', 'output_mode': 'json', 'ttl': '100000'}
                data = {
                "action": "rpa.runQuery",
                "parameters": {
                "data":SearchQuery,
                "url": splunkurl,
                "threshodLimit": 60,
                "Authorization": config_resp['STACK_SPLUNK_CALL_KEY']  
                   }
                 }
                data=json.dumps(data)
                r = requests.post(url = base_url, data = data,headers=headers, verify = cert)
                unique_id=r.json()['id']
                thresold=0
                responserul= base_url+"/{}".format(unique_id)
                time.sleep(2) 

                thresold=0
                aggregated_resp=[]
                
                while thresold<=60:
                  formated_str = ""
                  time.sleep(2)
                  response=requests.get(responserul,verify = cert,headers=headers)

                  if response.json().get('status') == "succeeded":
                    for item in response.json()['result']['result']:
                      Headers=item.keys()
                    break
                  elif response.json().get('status') == "failed":
                    dispatcher.utter_message('Currently it is taking longer time to fetch the report. Please try again by giving complete uri or lesser time.')
                    return[AllSlotsReset()]
                    break

                if len(response.json()['result']['result']) == 0:
                  dispatcher.utter_message('There is no report fetched for the search criteria')
                  return[AllSlotsReset()]

                Headers=list(Headers)
                Headers.remove("_span")
                Headers.remove("_time")
                Headers.insert(0,"_time")
                
                if response.json().get('status') == "succeeded":
                  t = time.localtime()
                  timestamp = time.strftime('%m-%d-%Y_%H%M%S', t)
                  splunkfile=("SplunkReport_"+timestamp+".csv")
                  pj = open(splunkfile,"w",newline="")
                  pjcsv=csv.writer(pj)
                  pjcsv.writerow(Headers)

                  for each in response.json().get('result').get("result"):
                    eachRow=[]
                    for eachH in Headers:
                      eachRow.append(each.get(eachH))
                    pjcsv.writerow(eachRow)
                  pj.close()
                  with open(splunkfile) as splunkf:
                    Content = splunkf.read()
                  print(Content)
                  data = open(splunkfile, "rb").read()
                  encoded = (base64.b64encode(data))
                  message={"payload":"Splunkdata","data":encoded}
                  dispatcher.utter_message(text="Please click here to download report:",json_message=message)
                  os.remove(splunkfile)

            except Exception as e:
              if 'expecting value' in str(e).lower():
                dispatcher.utter_message('Error: Incorrect api URL')
              elif 'out of range' in str(e).lower():
                dispatcher.utter_message('Error: No results for given values')
              elif 'SSLError' in str(e).lower():
                dispatcher.utter_message('Error: SSL certificate issue occured')
              else:
                dispatcher.utter_message(e)
            return [AllSlotsReset()]
        elif splunk_option == 'perf_api':
            payload={}
            response = requests.request("POST", splunk_api, headers=headers, data = payload,verify = cert)
            try:
              if response.status_code==201:
                token=(response.json()['token'])
                base_url= config_resp['STACK_SPLUNK_URL_EXEC'] 
                headers={'X-Auth-Token':token,'content-type':'application/json'}
                splunkurl= config_resp['STACK_SPLUNK_URL'] 
                SearchQuery= {'search': 'search index=apigee_prod URI=* ' +splunk_uri+'* | eval TotalTime = TransactionSentEndtime - TransactionReceivedStartTime | timechart span=2m count as TotalCount count(eval(Status=200 OR Status=404)) as SuccessCount count(eval(Status=504)) as TimeoutCount count(eval(TotalTime>1000)) as "highRespTimeCount(>1s)" eval(round(avg(TotalTime),0)) as "Avg Time(ms)" eval(round(perc90(TotalTime),0)) as "90% Time(ms)" eval(round(perc98(TotalTime),0)) as "98% Time(ms)" max(TotalTime) as Total_Max min(TotalTime) as Total_Min', 'earliest_time': '' + splunk_time + '' , 'latest_time': '' + splunk_time1 + '', 'output_mode': 'json', 'ttl': '100000'}
                data = {
                "action": "rpa.runQuery",
                "parameters": {
                "data":SearchQuery,
                "url": splunkurl,
                "threshodLimit": 60,
                "Authorization": config_resp['STACK_SPLUNK_CALL_KEY']  
                   }
                 }
                data=json.dumps(data)
                r = requests.post(url = base_url, data = data,headers=headers, verify = cert)
                unique_id=r.json()['id']
                thresold=0
                responserul= base_url+"/{}".format(unique_id)
                time.sleep(2) 

                thresold=0
                aggregated_resp=[]
                
                while thresold<=60:
                  formated_str = ""
                  time.sleep(2)
                  response=requests.get(responserul,verify = cert,headers=headers)

                  if response.json().get('status') == "succeeded":
                    for item in response.json()['result']['result']:
                      Headers=item.keys()
                    break
                  elif response.json().get('status') == "failed":
                    dispatcher.utter_message('Currently it is taking longer time to fetch the report. Please try again by giving complete uri or lesser time.')
                    return[AllSlotsReset()]
                    break

                if len(response.json()['result']['result']) == 0:
                  dispatcher.utter_message('There is no report fetched for the search criteria')
                  return[AllSlotsReset()]

                Headers=list(Headers)
                #Headers.remove('_span','Total_Max','Avg Time(ms)','_time','TotalCount','TimeoutCount','Total_Min','SuccessCount','90% Time(ms)','98% Time(ms)')
                Headers.remove('_span')
                Headers.remove('Total_Max')
                Headers.remove('Avg Time(ms)')
                Headers.remove('_time')
                Headers.remove('TotalCount')
                Headers.remove('TimeoutCount')
                Headers.remove('Total_Min')
                Headers.remove('SuccessCount')
                Headers.remove('90% Time(ms)')
                Headers.remove('98% Time(ms)')
                Headers.insert(0,'_time')
                Headers.insert(1,'TotalCount')
                Headers.insert(2,'SuccessCount')
                Headers.insert(3,'TimeoutCount')
                Headers.insert(5,'Avg Time(ms)')
                Headers.insert(6,'90% Time(ms)')
                Headers.insert(7,'98% Time(ms)')
                Headers.insert(8,'Total_Max')
                Headers.insert(9,'Total_Min')
                
                
                if response.json().get('status') == "succeeded":
                  t = time.localtime()
                  timestamp = time.strftime('%m-%d-%Y_%H%M%S', t)
                  splunkfile=("SplunkReport_"+timestamp+".csv")
                  pj = open(splunkfile,"w",newline="")
                  pjcsv=csv.writer(pj)
                  pjcsv.writerow(Headers)

                  for each in response.json().get('result').get("result"):
                    eachRow=[]
                    for eachH in Headers:
                      eachRow.append(each.get(eachH))
                    pjcsv.writerow(eachRow)
                  pj.close()
                  with open(splunkfile) as splunkf:
                    Content = splunkf.read()
                  print(Content)
                  data = open(splunkfile, "rb").read()
                  encoded = (base64.b64encode(data))
                  message={"payload":"Splunkdata","data":encoded}
                  dispatcher.utter_message(text="Please click here to download report:",json_message=message)
                  os.remove(splunkfile)
                  return [AllSlotsReset()]

            except Exception as e:
              if 'expecting value' in str(e).lower():
                dispatcher.utter_message('Error: Incorrect api URL')
              elif 'out of range' in str(e).lower():
                dispatcher.utter_message('Error: No results for given values')
              elif 'SSLError' in str(e).lower():
                dispatcher.utter_message('Error: SSL certificate issue occured')
              else:
                dispatcher.utter_message(e)
            return [AllSlotsReset()]

        elif splunk_option == 'res_status':
          


            payload={}
            response = requests.request("POST", splunk_api, headers=headers, data = payload,verify = cert)
            
            try:
              if response.status_code==201:
                token=(response.json()['token'])
                base_url= config_resp['STACK_SPLUNK_URL_EXEC'] 
                headers={'X-Auth-Token':token,'content-type':'application/json'}
                splunkurl= config_resp['STACK_SPLUNK_URL'] 
                SearchQuery= {'search': 'search index=apigee_prod source="tcp:9993" URI=*'+splunk_uri +'* NOT Status=200 | rex field=URI "(?<API>(^[^?]+))"  | rex field=API mode=sed "s/[0-9A-Z-~_]{1,50}//g"| eval TotalTime = TransactionSentEndtime - TransactionReceivedStartTime | eval BackendTime =  ResponseReceivedEndTime-RequestSentEndTime | eval ProxyTime = TotalTime - BackendTime |stats  max(TotalTime) max(BackendTime) max(ProxyTime) by API | rename max(TotalTime) as Max_Total_Time_in_ms max(BackendTime) as Max_Backend_Time_in_ms max(ProxyTime) as Max_Proxy_Time_in_msURI', 'earliest_time': '' + splunk_time + '', 'latest_time': '' + splunk_time1 + '', 'output_mode': 'json', 'ttl': '100000'}
                data = {
                "action": "rpa.runQuery",
                "parameters": {
                "data":SearchQuery,
                "url": splunkurl,
                "threshodLimit": 60,
                "Authorization": config_resp['STACK_SPLUNK_CALL_KEY']  
                   }
                 }
                 
                data=json.dumps(data)
                r = requests.post(url = base_url, data = data,headers=headers, verify = cert)
                unique_id=r.json()['id']
                thresold=0

                responserul= base_url+"/{}".format(unique_id)
                time.sleep(2) 

                thresold=0
                aggregated_resp={}

                while thresold<=60:
                  formated_str = ""
                  time.sleep(2)
                  response=requests.get(responserul,verify = cert,headers=headers)

                  if response.json().get('status') == "succeeded":
                    for item in response.json()['result']['result']:
                      Headers=item.keys()
                    break
                  elif response.json().get('status') == "failed":
                    dispatcher.utter_message('Currently it is taking longer time to fetch the report. Please try again by giving complete uri or lesser time.')
                    return[AllSlotsReset()]
                    break

                if len(response.json()['result']['result']) == 0:
                  dispatcher.utter_message('There is no report fetched for the search criteria')
                  return[AllSlotsReset()]

                Headers=list(Headers)
                Headers.remove("API")
                Headers.insert(0,"API")
                Headers.remove("Max_Proxy_Time_in_msURI")
                Headers.insert(2,"Max_Proxy_Time_in_msURI")
                if response.json().get('status') == "succeeded":
                  t = time.localtime()
                  timestamp = time.strftime('%m-%d-%Y_%H%M%S', t)
                  splunkfile=("SplunkReport_"+timestamp+".csv")
                  pj = open(splunkfile,"w",newline="")
                  pjcsv=csv.writer(pj)
                  pjcsv.writerow(Headers)

                  for each in response.json().get('result').get("result"):
                    eachRow=[]
                    for eachH in Headers:
                      eachRow.append(each.get(eachH))
                    pjcsv.writerow(eachRow)
                  pj.close()
                  with open(splunkfile) as splunkf:
                    Content = splunkf.read()
                    print(Content)
                  data = open(splunkfile, "rb").read()
                  encoded = (base64.b64encode(data))
                  message={"payload":"Splunkdata","data":encoded}
                  dispatcher.utter_message(text="Please click here to download report:",json_message=message)
                  os.remove(splunkfile)

            except Exception as e:
              if 'expecting value' in str(e).lower():
                dispatcher.utter_message('Error: Incorrect api URL')
              elif 'out of range' in str(e).lower():
                dispatcher.utter_message('Error: No results for given values')
              elif 'SSLError' in str(e).lower():
                dispatcher.utter_message('Error: SSL certificate issue occured')
              else:
                dispatcher.utter_message(e)
            return [AllSlotsReset()]

        elif splunk_option == 'fetch_consumers':
            


            payload={}
            response = requests.request("POST", splunk_api, headers=headers, data = payload,verify = cert)
            
            try:
              if response.status_code==201:
                token=(response.json()['token'])
                base_url= config_resp['STACK_SPLUNK_URL_EXEC'] 
                headers={'X-Auth-Token':token,'content-type':'application/json'}
                splunkurl= config_resp['STACK_SPLUNK_URL']
                SearchQuery= {'search': 'search index=apigee_prod source="tcp:9993" URI=*'+splunk_uri +'* NOT Status=200 | rex field=URI "(?<API>(^[^?]+))" | rex field=API mode=sed "s/[0-9A-Z-~_]{1,50}//g"| stats count by URI Sender | rename Sender as Consumer', 'earliest_time': '-2d@d', 'latest_time': '' + splunk_time1 + '', 'output_mode': 'json', 'ttl': '100000'}
                data = {
                "action": "rpa.runQuery",
                "parameters": {
                "data":SearchQuery,
                "url": splunkurl,
                "threshodLimit": 60,
                "Authorization": config_resp['STACK_SPLUNK_CALL_KEY']  
                   }
                 }
                 
                data=json.dumps(data)
                r = requests.post(url = base_url, data = data,headers=headers, verify = cert)
                unique_id=r.json()['id']
                thresold=0

                responserul= base_url+"/{}".format(unique_id)
                time.sleep(2) 

                thresold=0
                aggregated_resp={}

                while thresold<=60:
                  formated_str = ""
                  time.sleep(2)
                  response=requests.get(responserul,verify = cert,headers=headers)
                    
                  if response.json().get('status') == "succeeded":
                    for item in response.json()['result']['result']:
                      Headers=item.keys()
                    break
                  elif response.json().get('status') == "failed":
                    dispatcher.utter_message('Currently it is taking longer time to fetch the report. Please try again by giving complete uri or lesser time.')
                    return[AllSlotsReset()]
                    break

                if len(response.json()['result']['result']) == 0:
                  dispatcher.utter_message('There is no report fetched for the search criteria')
                  return[AllSlotsReset()]

                Headers=list(Headers)
                Headers.remove("URI")
                Headers.insert(0,"URI")
                Headers.remove("count")
                Headers.insert(2,"count")
                if response.json().get('status') == "succeeded":
                  t = time.localtime()
                  timestamp = time.strftime('%m-%d-%Y_%H%M%S', t)
                  splunkfile=("SplunkReport_"+timestamp+".csv")
                  pj = open(splunkfile,"w",newline="")
                  pjcsv=csv.writer(pj)
                  pjcsv.writerow(Headers)

                  for each in response.json().get('result').get("result"):
                    eachRow=[]
                    for eachH in Headers:
                      eachRow.append(each.get(eachH))
                    pjcsv.writerow(eachRow)
                  pj.close()
                  with open(splunkfile) as splunkf:
                    Content = splunkf.read()
                  print(Content)
                  data = open(splunkfile, "rb").read()
                  encoded = (base64.b64encode(data))
                  message={"payload":"Splunkdata","data":encoded}
                  dispatcher.utter_message(text="Please click here to download report:",json_message=message)
                  os.remove(splunkfile)

            except Exception as e:
              if 'expecting value' in str(e).lower():
                dispatcher.utter_message('Error: Incorrect api URL')
              elif 'out of range' in str(e).lower():
                dispatcher.utter_message('Error: No results for given values')
              elif 'SSLError' in str(e).lower():
                dispatcher.utter_message('Error: SSL certificate issue occured')
              else:
                dispatcher.utter_message(e)
            return [AllSlotsReset()]

        elif splunk_option == 'target_host':
            


            payload={}
            response = requests.request("POST", splunk_api, headers=headers, data = payload,verify = cert)

            splunk_time = '-10m@m'
            
            try:
              if response.status_code==201:
                token=(response.json()['token'])
                base_url= config_resp['STACK_SPLUNK_URL_EXEC'] 
                headers={'X-Auth-Token':token,'content-type':'application/json'}
                splunkurl= config_resp['STACK_SPLUNK_URL']
                SearchQuery= {'search': 'search index=apigee_prod source="tcp:9993" URI=*'+splunk_uri +'* | rex field=URI "(?<API>(^[^?]+))" | rex field=API mode=sed "s/[0-9A-Z-~_]{1,50}//g"| stats count by API TargetHost', 'earliest_time': '' + splunk_time + '', 'latest_time': '' + splunk_time1 + '', 'output_mode': 'json', 'ttl': '100000'}
                data = {
                "action": "rpa.runQuery",
                "parameters": {
                "data":SearchQuery,
                "url": splunkurl,
                "threshodLimit": 60,
                "Authorization": config_resp['STACK_SPLUNK_CALL_KEY']  
                   }
                 }
                 
                data=json.dumps(data)
                r = requests.post(url = base_url, data = data,headers=headers, verify = cert)
                unique_id=r.json()['id']
                thresold=0

                responserul= base_url+"/{}".format(unique_id)
                time.sleep(2) 

                thresold=0
                aggregated_resp={}

                while thresold<=60:
                  formated_str = ""
                  time.sleep(2)
                  response=requests.get(responserul,verify = cert,headers=headers)
                    
                  if response.json().get('status') == "succeeded":
                    for item in response.json()['result']['result']:
                      Headers=item.keys()
                    break
                  elif response.json().get('status') == "failed":
                    dispatcher.utter_message('Currently it is taking longer time to fetch the report. Please try again by giving complete uri or lesser time.')
                    return[AllSlotsReset()]
                    break

                if len(response.json()['result']['result']) == 0:
                  dispatcher.utter_message('There is no report fetched for the search criteria')
                  return[AllSlotsReset()]

                Headers=list(Headers)
                Headers.remove("API")
                Headers.remove("count")
                Headers.insert(0,"API")
                if response.json().get('status') == "succeeded":
                  t = time.localtime()
                  timestamp = time.strftime('%m-%d-%Y_%H%M%S', t)
                  splunkfile=("SplunkReport_"+timestamp+".csv")
                  pj = open(splunkfile,"w",newline="")
                  pjcsv=csv.writer(pj)
                  pjcsv.writerow(Headers)

                  for each in response.json().get('result').get("result"):
                    eachRow=[]
                    for eachH in Headers:
                      eachRow.append(each.get(eachH))
                    pjcsv.writerow(eachRow)
                  pj.close()
                  with open(splunkfile) as splunkf:
                    Content = splunkf.read()
                  print(Content)
                  data = open(splunkfile, "rb").read()
                  encoded = (base64.b64encode(data))
                  message={"payload":"Splunkdata","data":encoded}
                  dispatcher.utter_message(text="Please click here to download report:",json_message=message)
                  os.remove(splunkfile)

            except Exception as e:
              if 'expecting value' in str(e).lower():
                dispatcher.utter_message('Error: Incorrect api URL')
              elif 'out of range' in str(e).lower():
                dispatcher.utter_message('Error: No results for given values')
              elif 'SSLError' in str(e).lower():
                dispatcher.utter_message('Error: SSL certificate issue occured')
              else:
                dispatcher.utter_message(e)
            return [AllSlotsReset()]

        else:
            dispatcher.utter_message("Invalid input")
            return [AllSlotsReset()]
          
class ActionPSEDAloginApi(Action):
    def name(self):
        return "action_loginapi"
    def run(self, dispatcher, tracker, domain):
        events = tracker.current_state()['events']
        user_events = []
        user_events=[e for e in events if e['event'] == 'user']
        metadata=user_events[-1]['metadata']
        #####print(user_events[-1]['metadata'])
        auth_token=metadata['authorization']
        login_usernm=tracker.sender_id
        ##print("authorization",auth_token)
        ###print("login-usernm",login-usernm)
        #login_usernm=metadata['login-usernm']
        login = tracker.get_slot('login')
        API_ENDPOINT=config_resp["LoginAPI"]
        r = requests.get(API_ENDPOINT,verify = cert, headers={"authorization":auth_token,"login-usernm":login_usernm}) 
        r=r.json()
        #print("APIResponse",r)
        if "count" in r:
         count=r["count"]
         dispatcher.utter_message("{count} logins today".format(count=count))
        else:
         dispatcher.utter_message("No results found")
        return [SlotSet("login", None)]


class submemGrpApiAction(Action):
    def name(self):
        return "action_submem"

    def run(self, dispatcher, tracker, domain):
     try:
        events = tracker.current_state()['events']
        user_events = []
        user_events=[e for e in events if e['event'] == 'user']
        metadata=user_events[-1]['metadata']
        #print(user_events[-1]['metadata'])
        auth_token=metadata['authorization']
        login_usernm=tracker.sender_id
        #login_usernm=metadata['login-usernm']
        grpid = tracker.get_slot('edagroup')
        src = tracker.get_slot('edasrc')
        Content_Type= "application/json"
        API_ENDPOINT=config_resp["groupActMemSubAPI"]
        API_ENDPOINT=API_ENDPOINT+"?groupId="+grpid.upper()+"&sourceSystem="+src.upper()
        r = requests.get(url = API_ENDPOINT,headers={"Content-type":"application/json","authorization":auth_token,"login-usernm":login_usernm},verify = cert) 
        r=r.json()
        
        if 'rltnshpCount' in r:
         rltnshpCount=r["rltnshpCount"]
         for rltnshpCount in rltnshpCount:
          dispatcher.utter_message("In group {grp} and src {src}\n ".format(grp=grpid,src=src))
          dispatcher.utter_message("total members -{tm} ,subscribers- {sub}".format(tm=rltnshpCount["totalMembersCount"],sub=rltnshpCount["subscriberCount"]))

        else:
          dispatcher.utter_message("No Data found for groupid {grpid} and src {src}".format(grpid=grpid,src=src))
        return [SlotSet("src", None),SlotSet("grouprex", None),SlotSet("time", None),
        SlotSet("srcsys", None),SlotSet("groupid", None)]
     except:
      dispatcher.utter_message("Unable to get the results")

class regHourlyAction(Action):
    def name(self):
        return "action_regHourly"

    def run(self, dispatcher, tracker, domain):
     try:
      #dateTime = tracker.get_slot('time')
      events = tracker.current_state()['events']
      user_events = []
      user_events=[e for e in events if e['event'] == 'user']
      metadata=user_events[-1]['metadata']
      #print(user_events[-1]['metadata'])
      auth_token=metadata['authorization']
      login_usernm=tracker.sender_id
      #login_usernm=metadata['login-usernm']
      dateTime=None
      if tracker.get_slot('datetimerange') is not None:
       dateTime = tracker.get_slot('datetimerange')
      elif tracker.get_slot('daterange') is not None:
       dateTime = tracker.get_slot('daterange')
      elif tracker.get_slot('date') is not None:
       dateTime = tracker.get_slot('date')

       
      sub = tracker.get_slot('subscriber')
      if dateTime is None:
       API_ENDPOINT=config_resp["registerAPI"]
       r = requests.get(API_ENDPOINT,verify = cert, headers={"authorization":auth_token,"login-usernm":login_usernm})
       r=r.json()
       if "count" in r:
        count=r["count"]
        dispatcher.utter_message("{count} are the total registered members\n".format(count=count))
       else:
        dispatcher.utter_message("No results found\n".format(count=count))

      else:
       try:
        format = "%m/%d/%Y %H:%M:%S"
        timestamp = datetime.now().strftime("%H:%M:%S")
        if "start_date" in dateTime or "start_time" in dateTime:
         if "start_time" in dateTime:
          dateTimeTo=dateTime["end_time"]
          dateTimeFrom=dateTime["start_time"]
          dateTimeTo=datetime.strptime(dateTimeTo[0:19],"%Y-%m-%d %H:%M:%S")
          dateTimeToC=datetime.strftime(dateTimeTo, format)
          dateTimeFrom=datetime.strptime(dateTimeFrom[0:19],"%Y-%m-%d %H:%M:%S")
          dateTimeFromC=datetime.strftime(dateTimeFrom, format)
          
         
         else:
          format = "%m/%d/%Y"
          dateTimeTo=dateTime["end_date"]
          dateTimeFrom=dateTime["start_date"]
          dateTimeTo=datetime.strptime(dateTimeTo[0:10],"%Y-%m-%d")
          dateTimeToC=datetime.strftime(dateTimeTo, format)
          dateTimeFrom=datetime.strptime(dateTimeFrom[0:10],"%Y-%m-%d")
          dateTimeFromC=datetime.strftime(dateTimeFrom, format)

         

         
         dateDiff=abs((dateTimeTo - dateTimeFrom).days)
         monthsDiff=dateDiff/30
         yearsDiff=dateDiff/365
         fromDate=dateTimeFromC
         toDate=dateTimeToC
        
         
         
         if int(yearsDiff) >=1:
          span="Yearly"
         elif int(monthsDiff) >= 1:
          span="Monthly"
         elif int(dateDiff) >= 1:
          span="Daily"
         else:
          span="Hourly"  
         data={"fromDate":fromDate,"toDate":toDate,"span":span}   
         #print("Difference in dates \n",dateDiff)
         #print("Difference in dates rounded \n",int(dateDiff))
         #print("Difference in months \n",monthsDiff)
         #print("Difference in months rounded  \n",int(monthsDiff))
         #print("Difference in years\n",yearsDiff)
         #print("Difference in years\n rounded ",int(yearsDiff))
         
        else:
         dateTime=datetime.strptime(dateTime[0:10],"%Y-%m-%d")
         format="%m/%d/%Y"
         dateTime=datetime.strftime(dateTime, format)
         fromDate=dateTime
         toDate=dateTime
         span="Daily"
         timestamp="00:00:00"
         data={"fromDate":fromDate,"toDate":toDate+' '+timestamp,"span":span}
         
        API_ENDPOINT=config_resp["registerAPITrend"]
        Content_Type= "application/json"
        data=json.dumps(data)
        if datetime.strftime(datetime.now(), format) < toDate:
          dispatcher.utter_message('You entered a future date, Please provide correct date')
          return [AllSlotsReset()]       
        r = requests.post(url = API_ENDPOINT,data=data,headers={"Content-type":"application/json","authorization":auth_token,"login-usernm":login_usernm},verify = cert)
        r=r.json()
        if len(r)!=0:
         dispatcher.utter_message("Here are the Registration Details\n")
         dispatcher.utter_message("from "+fromDate+ " to " + toDate+"\n")
         for dic in r:
          dispatcher.utter_message("On {date} registered users are {reg}\n".format(date=dic["x"],reg=dic["y"]))
        else:
         dispatcher.utter_message("No Results Found")
        
       except Exception as e:
        dispatcher.utter_message("Unabel to fetch the results")
        return [SlotSet("datetimerange", None),SlotSet("daterange", None),SlotSet("date", None)]
      
       
      return [SlotSet("datetimerange", None),SlotSet("daterange", None),SlotSet("date", None)]
     except Exception as e:
      #dispatcher.utter_message("Exception",e)   
      dispatcher.utter_message("Unable to fetch the results")
      return [SlotSet("datetimerange", None),SlotSet("daterange", None),SlotSet("date", None)]


class groupRegistrationDtls(Action):
    def name(self):
        return "action_groupRegistrationDtls"

    def run(self, dispatcher, tracker, domain):
     try:
      events = tracker.current_state()['events']
      user_events = []
      user_events=[e for e in events if e['event'] == 'user']
      metadata=user_events[-1]['metadata']
      #print(user_events[-1]['metadata'])
      auth_token=metadata['authorization']
      login_usernm=tracker.sender_id
      #login_usernm=metadata['login-usernm']
      groupId = tracker.get_slot('edagroup')
      srcSys = tracker.get_slot('edasrc')
      #dateTime = tracker.get_slot('time')
      dateTime=None
      if tracker.get_slot('datetimerange') is not None:
       dateTime = tracker.get_slot('datetimerange')

      elif tracker.get_slot('daterange') is not None:
       dateTime = tracker.get_slot('daterange')
      elif tracker.get_slot('date') is not None:
       dateTime = tracker.get_slot('date')
      if dateTime is None:
       API_ENDPOINT=config_resp["groupregisterAPI"]
       data={ "groupId":groupId.upper(),"srcSystem":srcSys.upper()}
       data=json.dumps(data)
       r = requests.post(url = API_ENDPOINT,data=data,headers={"Content-type":"application/json","authorization":auth_token,"login-usernm":login_usernm},verify = cert) 
       r=r.json()
       if "count" in r:
        dispatcher.utter_message("total registered members in group {grp} source {src} are {count}\n".format(grp=groupId,src=srcSys,count=r["count"]))
       else:
        dispatcher.utter_message("No results found for  group {grp} source {src} ".format(grp=groupId,src=srcSys))

      else:
       try:
        format = "%m/%d/%Y %H:%M:%S"
        timestamp = datetime.now().strftime("%H:%M:%S")
        if "start_date" in dateTime or "start_time" in dateTime:
         if "start_time" in dateTime:
          dateTimeTo=dateTime["end_time"]
          dateTimeFrom=dateTime["start_time"]
          dateTimeTo=datetime.strptime(dateTimeTo[0:19],"%Y-%m-%d %H:%M:%S")
          dateTimeToC=datetime.strftime(dateTimeTo, format)
          dateTimeFrom=datetime.strptime(dateTimeFrom[0:19],"%Y-%m-%d %H:%M:%S")
          dateTimeFromC=datetime.strftime(dateTimeFrom, format)
         
         
         else:
          format = "%m/%d/%Y"
          dateTimeTo=dateTime["end_date"]
          dateTimeFrom=dateTime["start_date"]
          dateTimeTo=datetime.strptime(dateTimeTo[0:10],"%Y-%m-%d")
          dateTimeToC=datetime.strftime(dateTimeTo, format)
          dateTimeFrom=datetime.strptime(dateTimeFrom[0:10],"%Y-%m-%d")
          dateTimeFromC=datetime.strftime(dateTimeFrom, format)
          

         
         dateDiff=abs((dateTimeTo - dateTimeFrom).days)
         monthsDiff=dateDiff/30
         yearsDiff=dateDiff/365
         fromDate=dateTimeFromC
         toDate=dateTimeToC
        

         if int(yearsDiff) >=1:
          span="Yearly"
         elif int(monthsDiff) >= 1:
          span="Monthly"
         elif int(dateDiff) >= 1:
          span="Daily"
         else:
          span="Hourly"     
         data={"groupId":groupId.upper(),"srcSystem":srcSys.upper(),"graphRequest":"Registrations","fromDate":fromDate,"toDate":toDate,"span":span}
        else:
         dateTime=datetime.strptime(dateTime[0:10],"%Y-%m-%d")
         format="%m/%d/%Y"
         dateTime=datetime.strftime(dateTime, format)
         fromDate=dateTime
         toDate=dateTime
         span="Daily"
         timestamp="00:00:00"
         data={"groupId":groupId.upper(),"srcSystem":srcSys.upper(),"graphRequest":"Registrations","fromDate":fromDate,"toDate":toDate+' '+timestamp,"span":span}
         
         

        API_ENDPOINT=config_resp["groupregisterAPITrend"]
        Content_Type= "application/json"
        data=json.dumps(data)

        if datetime.strftime(datetime.now(), format) < toDate:
          dispatcher.utter_message('You entered a future date, Please provide correct date')
          return [AllSlotsReset()] 

        r = requests.post(url = API_ENDPOINT,data=data,headers={"Content-type":"application/json","authorization":auth_token,"login-usernm":login_usernm},verify = cert) 
        r=r.json()
        if len(r)!=0:
         dispatcher.utter_message("Here are the Registration Details for group {grp} src {src}\n".format(grp=groupId,src=srcSys))
         dispatcher.utter_message("from "+fromDate+ " to " + toDate)

         for dic in r:
          dispatcher.utter_message("On {date} registered users are {reg}\n".format(date=dic["x"],reg=dic["y"]))
        else:
         dispatcher.utter_message("No Results Found")
        
       except:
         dispatcher.utter_message("Unable to fetch the results.")
         return [SlotSet("grouprex", None),SlotSet("src", None),
      SlotSet("srcsys", None),SlotSet("groupid", None),SlotSet("datetimerange", None),SlotSet("daterange", None),SlotSet("date", None)]
     
       
      return [SlotSet("grouprex", None),SlotSet("src", None),
      SlotSet("srcsys", None),SlotSet("groupid", None),SlotSet("datetimerange", None),SlotSet("daterange", None),SlotSet("date", None)]
     except:
      dispatcher.utter_message("Unable to fetch the results")
      return [SlotSet("grouprex", None),SlotSet("src", None),
      SlotSet("srcsys", None),SlotSet("groupid", None),SlotSet("datetimerange", None),SlotSet("daterange", None),SlotSet("date", None)]


class groupSubscRegistrationDtls(Action):
    def name(self):
        return "action_groupSubscRegistrationDtls"

    def run(self, dispatcher, tracker, domain):
     try:
      events = tracker.current_state()['events']
      user_events = []
      user_events=[e for e in events if e['event'] == 'user']
      metadata=user_events[-1]['metadata']
      #print(user_events[-1]['metadata'])
      auth_token=metadata['authorization']
      login_usernm=tracker.sender_id
      #login_usernm=metadata['login-usernm']
      groupId = tracker.get_slot('edagroup')
      srcSys = tracker.get_slot('edasrc')
      srcSys1 = tracker.get_slot('src1')
      #dateTime = tracker.get_slot('time')
      dateTime=None
      if tracker.get_slot('datetimerange') is not None:
       dateTime = tracker.get_slot('datetimerange')

      elif tracker.get_slot('daterange') is not None:
       dateTime = tracker.get_slot('daterange')
      elif tracker.get_slot('date') is not None:
       dateTime = tracker.get_slot('date')

      if dateTime is None:
       API_ENDPOINT=config_resp["groupsubregisterAPI"]
       data={ "groupId":groupId.upper(),"srcSystem":srcSys.upper()}
       data=json.dumps(data)
       r = requests.post(url = API_ENDPOINT,data=data,headers={"Content-type":"application/json","authorization":auth_token,"login-usernm":login_usernm},verify = cert) 
       r=r.json()
       if "count" in r:
        dispatcher.utter_message("total subscribers registered in group-{grp} source-{src} are {count}".format(grp=groupId,src=srcSys,count=r["count"]))
       else:
        dispatcher.utter_message("No results found in group-{grp} source-{src}".format(grp=groupId,src=srcSys))

      else:
       try:
        format = "%m/%d/%Y %H:%M:%S"
        timestamp = datetime.now().strftime("%H:%M:%S")
        if "start_date" in dateTime or "start_time" in dateTime:
         if "start_time" in dateTime:
          dateTimeTo=dateTime["end_time"]
          dateTimeFrom=dateTime["start_time"]
          dateTimeTo=datetime.strptime(dateTimeTo[0:19],"%Y-%m-%d %H:%M:%S")
          dateTimeToC=datetime.strftime(dateTimeTo, format)
          dateTimeFrom=datetime.strptime(dateTimeFrom[0:19],"%Y-%m-%d %H:%M:%S")
          dateTimeFromC=datetime.strftime(dateTimeFrom, format)
         
         
         else:
          format = "%m/%d/%Y"
          dateTimeTo=dateTime["end_date"]
          dateTimeFrom=dateTime["start_date"]
          dateTimeTo=datetime.strptime(dateTimeTo[0:10],"%Y-%m-%d")
          dateTimeToC=datetime.strftime(dateTimeTo, format)
          dateTimeFrom=datetime.strptime(dateTimeFrom[0:10],"%Y-%m-%d")
          dateTimeFromC=datetime.strftime(dateTimeFrom, format)
        

         
         
         
         
         
         dateDiff=abs((dateTimeTo - dateTimeFrom).days)
         monthsDiff=dateDiff/30
         yearsDiff=dateDiff/365
         fromDate=dateTimeFromC
         toDate=dateTimeToC
         if int(yearsDiff) >=1:
          span="Yearly"
         elif int(monthsDiff) >= 1:
          span="Monthly"
         elif int(dateDiff) >= 1:
          span="Daily"
         else:
          span="Hourly" 
         data={"groupId":groupId.upper(),"srcSystem":srcSys.upper(),"graphRequest":"subsregistration","fromDate":fromDate,"toDate":toDate,"span":span}
    
         #print("Difference in dates \n",dateDiff)
         #print("Difference in dates rounded \n",int(dateDiff))
         #print("Difference in months \n",monthsDiff)
         #print("Difference in months rounded  \n",int(monthsDiff))
         #print("Difference in years\n",yearsDiff)
         #print("Difference in years\n rounded ",int(yearsDiff))
        else:
         dateTime=datetime.strptime(dateTime[0:10],"%Y-%m-%d")
         format="%m/%d/%Y"
         dateTime=datetime.strftime(dateTime, format)
         fromDate=dateTime
         toDate=dateTime
         span="Daily"
         timestamp="00:00:00"
         data={"groupId":groupId.upper(),"srcSystem":srcSys.upper(),"graphRequest":"subsregistration","fromDate":fromDate,"toDate":toDate+' '+timestamp,"span":span}

        
        API_ENDPOINT=config_resp["groupregisterAPITrend"]
        Content_Type= "application/json"
        #data={"fromDate":fromDate,"toDate":toDate+' '+timestamp,"span":span}
        data=json.dumps(data)
        if datetime.strftime(datetime.now(), format) < toDate:
          dispatcher.utter_message('You entered a future date, Please provide correct date')
          return [AllSlotsReset()] 
        r = requests.post(url = API_ENDPOINT,data=data,headers={"Content-type":"application/json","authorization":auth_token,"login-usernm":login_usernm},verify = cert) 
        r=r.json()
        if len(r)!=0:
         dispatcher.utter_message("Here are the Subscribers Registration Details for group {grp} src {src}\n".format(grp=groupId,src=srcSys))
         dispatcher.utter_message("from "+fromDate+ " to " + toDate)

         for dic in r:
          dispatcher.utter_message("On {date} Subscribers registered  are {reg}\n".format(date=dic["x"],reg=dic["y"]))
        else:
         dispatcher.utter_message("No Results Found")
        
       except:
         dispatcher.utter_message("Unable to fetch the results.")
         return [SlotSet("grouprex", None),SlotSet("src", None),
      SlotSet("srcsys", None),SlotSet("groupid", None),SlotSet("datetimerange", None),SlotSet("daterange", None),SlotSet("date", None)]

         
       
      return [SlotSet("grouprex", None),SlotSet("src", None),
      SlotSet("srcsys", None),SlotSet("groupid", None),SlotSet("datetimerange", None),SlotSet("daterange", None),SlotSet("date", None)]
     except:
      dispatcher.utter_message("Unable to fetch the results")
      return [SlotSet("grouprex", None),SlotSet("src", None),
      SlotSet("srcsys", None),SlotSet("groupid", None),SlotSet("datetimerange", None),SlotSet("daterange", None),SlotSet("date", None)]



class slotReset(Action):
    def name(self):
        return "action_slot_reset"

    def run(self, dispatcher, tracker, domain):
     return [AllSlotsReset()]


class ActionPSEDAGroupRegForm(FormAction):
    def name(self) -> Text:
        return "ps_eda_groupreg_form"
    @staticmethod
    def required_slots(tracker: Tracker)-> List[Text]:
        return["edagroup","edasrc"]
    def slot_mappings(self) -> Dict[Text, Union[Dict, List[Dict]]]:
    

     return {
        
        "edagroup": [self.from_text()],
        "edasrc": [self.from_text()]
      }

    def submit(
    self,
    dispatcher: CollectingDispatcher,
    tracker: Tracker,
    domain: Dict[Text, Any],
        ) -> List[Dict]:
        #dispatcher.utter_message("")

        edagroup=tracker.get_slot('edagroup')
        edasrc=tracker.get_slot('edasrc')
        #if isinstance(edagroup, list):
         #edagroup=edagroup[0]
        #if isinstance(edasrc, list):
         #edasrc=edasrc[0]
        #print("Inside submit",edagroup)
        #return [SlotSet("edagroup", edagroup),SlotSet("edasrc", edasrc)]
        if isinstance(edagroup, list):
         edagroup=edagroup[1]
        if isinstance(edasrc, list):
         edasrc=edasrc[1]
        return [SlotSet("edagroup", edagroup),SlotSet("edasrc", edasrc)]
        

class ActionPSEDAReportsRegForm(FormAction):
    def name(self) -> Text:
        return "ps_eda_reportsreg_form"
    @staticmethod
    def required_slots(tracker: Tracker)-> List[Text]:
        return["edadate"]
    def slot_mappings(self) -> Dict[Text, Union[Dict, List[Dict]]]:
    

     return {
        
        "edadate": [self.from_text()]
      }
    def validate_edadate(self,Value: Text, dispatcher: CollectingDispatcher,tracker: Tracker,domain: Dict[Text, Any])->Dict[Text,Any]:
      if tracker.get_slot('datetimerange') is not None:
       dateTime = tracker.get_slot('datetimerange')

      elif tracker.get_slot('daterange') is not None:
       dateTime = tracker.get_slot('daterange')
      elif tracker.get_slot('date') is not None:
       dateTime = tracker.get_slot('date')

      try:
        format = "%m/%d/%Y %H:%M:%S"
        timestamp = datetime.now().strftime("%H:%M:%S")
        if "start_date" in dateTime or "start_time" in dateTime:
         if "start_time" in dateTime:
          dateTimeTo=dateTime["end_time"]
          dateTimeFrom=dateTime["start_time"]
          dateTimeTo=datetime.strptime(dateTimeTo[0:19],"%Y-%m-%d %H:%M:%S")
          dateTimeToC=datetime.strftime(dateTimeTo, format)
          dateTimeFrom=datetime.strptime(dateTimeFrom[0:19],"%Y-%m-%d %H:%M:%S")
          dateTimeFromC=datetime.strftime(dateTimeFrom, format)
         
         
         else:
          format = "%m/%d/%Y"
          dateTimeTo=dateTime["end_date"]
          dateTimeFrom=dateTime["start_date"]
          dateTimeTo=datetime.strptime(dateTimeTo[0:10],"%Y-%m-%d")
          dateTimeToC=datetime.strftime(dateTimeTo, format)
          dateTimeFrom=datetime.strptime(dateTimeFrom[0:10],"%Y-%m-%d")
          dateTimeFromC=datetime.strftime(dateTimeFrom, format)
          

         
         dateDiff=abs((dateTimeTo - dateTimeFrom).days)
         monthsDiff=dateDiff/30
         yearsDiff=dateDiff/365
         fromDate=dateTimeFromC
         toDate=dateTimeToC
        else:
         dateTime=datetime.strptime(dateTime[0:10],"%Y-%m-%d")
         format="%m/%d/%Y"
         dateTime=datetime.strftime(dateTime, format)
         fromDate=dateTime
         toDate=dateTime  
        if datetime.strftime(datetime.now(), format) < toDate:
          dispatcher.utter_message('You entered a future date, Please provide correct date')
          return {"edadate":None}
        else:
          return{"edadate":Value}
      except Exception as e:
            print(e)
            dispatcher.utter_message('something went wrong, Please provide correct date')
            return {"edadate":None}


    def submit(
    self,
    dispatcher: CollectingDispatcher,
    tracker: Tracker,
    domain: Dict[Text, Any],
        ) -> List[Dict]:
        #dispatcher.utter_message("")
        

        return [] 
class ActionPSEDAUsrSrcSlotSet(Action):
    def name(self):
        return "action_ps_eda_usrsrc_slotset"
    def run(self, dispatcher, tracker, domain):
      try:
        #edagroup = tracker.get_slot('grouprex')
        #edasrc = tracker.get_slot('src')
        message = (tracker.latest_message)['text']
        srcsys = tracker.get_slot('srcsys')
        
        if srcsys is not None:
         edasrc = message.split(srcsys, maxsplit=1)[-1].split(maxsplit=1)[0]
         #tracker.slots['edasrc'] = edasrc
         #print("edagroup",edagroup)
         #print("edasrc",edasrc)
        else:
         edasrc=None
      
        return [SlotSet("edasrc", edasrc)]
      except:
       #edagroup = tracker.get_slot('edagroup')
       edasrc = tracker.get_slot('edasrc')
       #print("edagroup",edagroup)
       #print("edasrc",edasrc)
       return [SlotSet("edasrc", edasrc)]
class ActionPSEDAUsrGrpSlotSet(Action):
    def name(self):
        return "action_ps_eda_usrgrp_slotset"
    def run(self, dispatcher, tracker, domain):
      try:
        #edagroup = tracker.get_slot('grouprex')
        #edasrc = tracker.get_slot('src')
        message = (tracker.latest_message)['text']
        groupid = tracker.get_slot('groupid')
        print("groupid",groupid)
        print("message",message)
        if groupid is not None:
         edagroup = message.split(groupid, maxsplit=1)[-1].split(maxsplit=1)[0]
         #tracker.slots['edagroup'] = edagroup
         #print("edagroup",edagroup)
         #print("edasrc",edasrc)
        else:
         edagroup=None
       
      
        return [SlotSet("edagroup", edagroup)]
      except:
       edagroup = tracker.get_slot('edagroup')
       #edasrc = tracker.get_slot('edasrc')
       #print("edagroup",edagroup)
       #print("edasrc",edasrc)
       return [SlotSet("edagroup", edagroup)]
class ActionPSEDAHcidSearch(Action):
  def name(self):
        return "action_ps_eda_hcidsearch"
  def run(self, dispatcher, tracker, domain):
      try:
        events = tracker.current_state()['events']
        user_events = []
        user_events=[e for e in events if e['event'] == 'user']
        metadata=user_events[-1]['metadata']
        #print(user_events[-1]['metadata'])
        auth_token=metadata['authorization']
        login_usernm=tracker.sender_id
        #login_usernm=metadata['login-usernm']
        hcid=tracker.get_slot('ps_eda_hcidform')
        API_ENDPOINT = config_resp['PS_EDA_HCID_SEARCH']
        HCID_LINK = config_resp['PS_EDA_HCID_SEARCH_LINK']
        API_ENDPOINT =API_ENDPOINT+hcid
        r = requests.get(url = API_ENDPOINT,headers={"Content-type":"application/json","authorization":auth_token,"login-usernm":login_usernm},verify = cert)
        r=r.json()
        buttons=[]
        dfCtrctInd=0
        
        if 'results' in r:  
         if len(r['results'])!=0:
          for res in r['results']:
           if 'defaultCntrct' in res and "**Encripted**" in res['hcid']:
            dispatcher.utter_message("This hcid belongs to restricted group\n")
            dispatcher.utter_message("Please use below link to search hcid for restricted groups\n")
            HCID_LINK_H='<a href="{}" target="_blank"><b>{}</b></a>'.format(HCID_LINK,HCID_LINK)
            dispatcher.utter_message(HCID_LINK_H)
            return[SlotSet("ps_eda_hcidform", None)]
   
           if res['hcid']==hcid and 'defaultCntrct' in res and res['defaultCntrct']=="Y":
             dfCtrctInd=1
             src=res['sourceSystem']
            
          if dfCtrctInd==0:
           hcidFound=0
           for res in r['results']:
            if res['hcid']==hcid:
              src=res['sourceSystem']
              hcidFound=1
              break
           if hcidFound==0:
              dispatcher.utter_message("Hcid not found\n")
              return[SlotSet("ps_eda_hcidform", None)]


          ##src=res['sourceSystem']
          API_ENDPOINT = config_resp['PS_EDA_HCID_DTLVIEW']
          #API_ENDPOINT =API_ENDPOINT+hcid+"/"+src
          data={"hcid":hcid,"srcSys":src.upper()}
          data=json.dumps(data)
          r = requests.post(url = API_ENDPOINT,data=data,headers={"Content-type":"application/json","authorization":auth_token,"login-usernm":login_usernm},verify = cert) 
          #r = requests.get(url = API_ENDPOINT,headers={"Content-type":"application/json"},verify = cert)
          r=r.json()
          if 'exceptions' in r:
              dispatcher.utter_message("MEMBER NOT FOUND for the given hcid-{hcid}\n".format(hcid=hcid))
              return[SlotSet("ps_eda_hcidform", None)]
          else:
              if 'members' in r:
               for members in r['members']:
                firstName=members['firstName']
                lastName=members['lastName']
                cirsBlocked=members['cirsBlocked']
                eligibletoRegister=members['eligibletoRegister']
                registrationStatus=members['registrationStatus']
                relationshipCd=members['relationshipCd']
                dob=members['dob']
                mcid=members['mcid']
                fnamlname=firstName+' '+lastName
                fnamlname1=firstName+'-'+lastName
                payload = "/ps_eda_hcidSearchName{\"ps_eda_hcidname\":\"" + fnamlname1 + "\",\"ps_eda_hcid\":\"" + hcid + "\",\"ps_eda_hcidsrc\":\"" + src + "\"}"
                data= {"title": fnamlname1, "payload":payload}
                buttons.append(data)
               
              
               message="Please click on the members below to see more information\n"
               #intent = tracker.latest_message['intent'].get('name')
               #if intent not in ['ps_eda_hcidSearchName']:
               dispatcher.utter_button_message(message, buttons)
             
               return[SlotSet("ps_eda_hcidform", None),SlotSet("ps_eda_hcid", hcid),SlotSet("ps_eda_hcidsrc", src)]
               
              else:
               dispatcher.utter_message("Unable to fetch the results\n")
               return[SlotSet("ps_eda_hcidform", None)]

            
            
         
             
            
            
            
        
          
           
           
         
         else:
          dispatcher.utter_message("No data found for the given hcid-{hcid}\n".format(hcid=hcid))
          return[SlotSet("ps_eda_hcidform", None)]
        else:
         dispatcher.utter_message("No data found for the given hcid-{hcid}\n".format(hcid=hcid))
         return[SlotSet("ps_eda_hcidform", None)]
         

          
      except Exception as e:
       dispatcher.utter_message(e)
       dispatcher.utter_message("Unable to fetch the results\n")
       return[SlotSet("ps_eda_hcidform", None)]


class ActionPSEDAHcidMembersProfile(Action):
  def name(self):
        return "action_ps_eda_hcidmemprof"
  def run(self, dispatcher, tracker, domain):
      try:
        events = tracker.current_state()['events']
        user_events = []
        user_events=[e for e in events if e['event'] == 'user']
        metadata=user_events[-1]['metadata']
        #print(user_events[-1]['metadata'])
        auth_token=metadata['authorization']
        login_usernm=tracker.sender_id
        #login_usernm=metadata['login-usernm']
        hcid=tracker.get_slot('ps_eda_hcid')
        src=tracker.get_slot('ps_eda_hcidsrc')
        hcidname=tracker.get_slot('ps_eda_hcidname')
        hcidfname,hcidlname=hcidname.split('-')
        #print("hcidfname",hcidfname)
        #print("hcidlname",hcidlname)
        API_ENDPOINT = config_resp['PS_EDA_HCID_DTLVIEW']
        #API_ENDPOINT =API_ENDPOINT+hcid+"/"+src
        #r = requests.get(url = API_ENDPOINT,headers={"Content-type":"application/json"},verify = cert)
        data={"hcid":hcid,"srcSys":src.upper()}
        data=json.dumps(data)
        r = requests.post(url = API_ENDPOINT,data=data,headers={"Content-type":"application/json","authorization":auth_token,"login-usernm":login_usernm},verify = cert) 
        r=r.json()
        if 'exceptions' in r:
         dispatcher.utter_message("MEMBER NOT FOUND for the given hcid-{hcid}\n".format(hcid=hcid))
        else:
         if 'members' in r:
          for members in r['members']:
           firstName=members['firstName']
           lastName=members['lastName']
           if firstName==hcidfname and lastName==hcidlname:
            cirsBlocked=members['cirsBlocked']
            eligibletoRegister=members['eligibletoRegister']
            #print("eligibletoRegister",eligibletoRegister)
            registrationStatus=members['registrationStatus']
            relationshipCd=members['relationshipCd']
            mcid=members['mcid']
            dispatcher.utter_message("cirsBlocked-{hicdc}    eligibletoRegister-{hicde}    registrationStatus-{hicdr}".format(hicdc=cirsBlocked,
             hicde=eligibletoRegister,hicdr=registrationStatus))
            dispatcher.utter_message("mcid-{hicdm}    relationshipCd-{hicdrl}".format(
             hicdm=mcid,hicdrl=relationshipCd))
            dispatcher.utter_message('More information can be found from below link\n') 
            mbrProfileAPILink = config_resp['PS_EDA_HCID_MEMPROFILE']
            mbrProfileAPILink =mbrProfileAPILink+mcid+"/"+hcid+"/member-info"
            mbrProfileAPILinkH='<a href="{}" target="_blank"><b>{}</b></a>'.format(mbrProfileAPILink,mbrProfileAPILink)
            dispatcher.utter_message(mbrProfileAPILinkH)
         else:
          dispatcher.utter_message("Unable to fetch results")
        return []  
      except Exception as e:
       dispatcher.utter_message(e)
       dispatcher.utter_message("Unable to fetch the results\n")
       



class ActionPSEDAHcidSearchForm(FormAction):
    def name(self) -> Text:
        return "ps_eda_hcidsearch_form"
    @staticmethod
    def required_slots(tracker: Tracker)-> List[Text]:
        return["ps_eda_hcidform"]
    def slot_mappings(self) -> Dict[Text, Union[Dict, List[Dict]]]:
    

     return {
        
        "ps_eda_hcidform": [self.from_text()]
      }

    def submit(
    self,
    dispatcher: CollectingDispatcher,
    tracker: Tracker,
    domain: Dict[Text, Any],
        ) -> List[Dict]:
     return [] 
class PSEDAHCIDFormSlotReset(Action):
    def name(self):
        return "action_ps_eda_hcidform_slotreset"

    def run(self, dispatcher, tracker, domain):
     return[SlotSet("ps_eda_hcidform", None)]

class ActionPSIDCMSNMCdateForm(FormAction):
    def name(self) -> Text:
        return "ps_idcms_nmcdate_form"
    @staticmethod
    def required_slots(tracker: Tracker)-> List[Text]:
        return["ps_idcms_nmcdate"]
    def slot_mappings(self) -> Dict[Text, Union[Dict, List[Dict]]]:
    

     return {
        
        "ps_idcms_nmcdate": [self.from_text()]
      }

    def submit(
    self,
    dispatcher: CollectingDispatcher,
    tracker: Tracker,
    domain: Dict[Text, Any],
        ) -> List[Dict]:
        return []

class actionPSIDCMSSpanDetails(Action):
    def name(self):
        return "action_ps_idcms_span_details"

    def run(self, dispatcher, tracker, domain):
     try:
      #dateTime = tracker.get_slot('time')
      events = tracker.current_state()['events']
      user_events = []
      user_events=[e for e in events if e['event'] == 'user']
      metadata=user_events[-1]['metadata']
      #print(user_events[-1]['metadata'])
      auth_token=metadata['authorization']
      login_usernm=tracker.sender_id
      #login_usernm=metadata['login-usernm']
      dateTime=None
      if tracker.get_slot('datetimerange') is not None:
       dateTime = tracker.get_slot('datetimerange')

      elif tracker.get_slot('daterange') is not None:
       dateTime = tracker.get_slot('daterange')
      elif tracker.get_slot('date') is not None:
       dateTime = tracker.get_slot('date')
      if dateTime is not None:
       try:
        print("dateTime",dateTime)
        #format = "%m/%d/%Y %H:%M:%S"
        timestamp = dt.date.today() # today's date
        #print("Today's date",timestamp)
        if "start_date" in dateTime or "start_time" in dateTime:
         if "start_time" in dateTime:
          dateTimeTo=dateTime["end_time"]
          dateTimeFrom=dateTime["start_time"]
         else:
          #format = "%m/%d/%Y"
          dateTimeTo=dateTime["end_date"]+" 23:59:59"
          dateTimeFrom=dateTime["start_date"]

             
         data={"type":"chart","graphRequest":"nmc","date":dateTimeFrom,"toDate":dateTimeTo}
        else: # If there is only date
          fromDate=dateTime
          timestamp="23:59:59"
          data={"type":"chart","graphRequest":"nmc","date":fromDate,"toDate":fromDate+' '+timestamp}
         
         

        #API_ENDPOINT="https://smarthelp-uat.anthem.com/smarthelp/smarthelpapi/idcms-summary/nmc/chart"
        API_ENDPOINT=config_resp["PS_IDCMS_NMC"]
        #print("API_ENDPOINT",API_ENDPOINT)
        Content_Type= "application/json"
        data=json.dumps(data)
        r = requests.post(url = API_ENDPOINT,data=data,headers={"Content-type":Content_Type,"meta-timezone":"Asia/Calcutta","authorization":auth_token,"login-usernm":login_usernm},verify = cert) 
        r=r.json()
        if 'exceptions' in r:
         dispatcher.utter_message("Unable to fetch the results.")
         return [SlotSet("datetimerange", None),SlotSet("daterange", None),SlotSet("date", None)]
        if len(r)!=0:
         #dispatcher.utter_message("Here are the NMC count Details\n")
         #dispatcher.utter_message("from "+fromDate+ " to " + fromDate+' '+timestamp)

         for dic in r:
          dispatcher.utter_message("NMC count Details\n Digital Count is {}\n Physical Count is {}\n Skinny Count is {}\n Digital Skinny Count is {}\n".format(dic["digitalCount"], dic["physicalCount"], dic["skinnyCount"], dic["digSkinnyCount"]))
          totalCount = (dic["digitalCount"] + dic["physicalCount"]+ dic["skinnyCount"]+ dic["digSkinnyCount"])/100
          dispatcher.utter_message("NMC Statistics in percentage % \n Digital Count is {}\n Physical Count is {}\n Skinny Count is {}\n Digital Skinny Count is {}\n".format(round(dic["digitalCount"]/totalCount,2), round(dic["physicalCount"]/totalCount,2), round(dic["skinnyCount"]/totalCount,2), round(dic["digSkinnyCount"]/totalCount,2)))
        else:
         dispatcher.utter_message("No Results Found")
      

       except Exception as e:
         dispatcher.utter_message("Unable to fetch the results.", e)
         return [SlotSet("datetimerange", None),SlotSet("daterange", None),SlotSet("date", None)]
     
       
       return [SlotSet("datetimerange", None),SlotSet("daterange", None),SlotSet("date", None)]
     
      else:
        dispatcher.utter_message("Invalid date/ date range, Please enter right format")

     except Exception as e:
      dispatcher.utter_message("Unable to fetch the results outside loop",e)
      return [SlotSet("datetimerange", None),SlotSet("daterange", None),SlotSet("date", None)]


class actionPSIDCMSNmcReport(Action):
    
    def name(self) -> Text:
         return "action_ps_idcms_nmc_reports"
    def run(self, dispatcher: CollectingDispatcher,
            tracker: Tracker,
            domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        try:
            #message = (tracker.latest_message)['text']
            events = tracker.current_state()['events']
            user_events = []
            user_events=[e for e in events if e['event'] == 'user']
            metadata=user_events[-1]['metadata']
            #print(user_events[-1]['metadata'])
            auth_token=metadata['authorization']
            login_usernm=tracker.sender_id
            #login_usernm=metadata['login-usernm']
            span_details=tracker.get_slot('ps_idcms_span_details')

            #print("span_details",span_details)
            dispatcher.utter_message("NMC details for {} is".format(span_details))
            
            
            today = dt.date.today()

            if span_details == "today":
                fromDate = today.strftime("%m/%d/%Y")
                toDate = today.strftime("%m/%d/%Y 23:59:59")
                data={"type":"chart","graphRequest":"nmc","date":fromDate,"toDate":toDate}
            elif span_details == "this week":
                weekday = today.weekday()
                start_delta = timedelta(days=weekday+1)
                start_of_week = today - start_delta
                start_of_week_str = (start_of_week).strftime("%m/%d/%Y")

                
                end_of_week = start_of_week + timedelta(7)
                end_of_week_str = (end_of_week).strftime("%m/%d/%Y")
                data={"type":"chart","graphRequest":"nmc","date":start_of_week_str,"toDate":end_of_week_str}
            elif span_details == "week":
                weekday = today.weekday()
                if weekday == 6:
                    start_delta = timedelta(days=weekday+1) # On sunday, needs to consider last week as previous week, not present week
                else:
                    start_delta = timedelta(days=weekday+1,weeks=1) # Monday
                start_of_week = today - start_delta
                start_of_week_str = (start_of_week).strftime("%m/%d/%Y")
                #print("start_of_week", start_of_week)
                end_of_week_str = (start_of_week + timedelta(7)).strftime("%m/%d/%Y")
                #print("end_of_week",end_of_week_str)
                #print(type(end_of_week_str))
                data={"type":"chart","graphRequest":"nmc","date":start_of_week_str,"toDate":end_of_week_str}
            elif span_details == "month":
                lastMonth_end = today.replace(day=1) # beginning of current month
                lastMonth_start = (today.replace(day=1) - timedelta(days=1)).replace(day=1) # beginning of last month
                #print(lastMonth_start, lastMonth_end)
                data={"type":"chart","graphRequest":"nmc","date":lastMonth_start.strftime("%m/%d/%Y"),"toDate":lastMonth_end.strftime("%m/%d/%Y")}

            #API_ENDPOINT="https://smarthelp-uat.anthem.com/smarthelp/smarthelpapi/idcms-summary/nmc/chart"
            API_ENDPOINT=config_resp["PS_IDCMS_NMC"]
            
            Content_Type= "application/json"
            data=json.dumps(data)
            r = requests.post(url = API_ENDPOINT,data=data,headers={"Content-type":Content_Type,"meta-timezone":"Asia/Calcutta","authorization":auth_token,"login-usernm":login_usernm},verify = cert) 
            r=r.json()
            if 'exceptions' in r:
             dispatcher.utter_message("Unable to fetch the results.")
             return [SlotSet("datetimerange", None),SlotSet("daterange", None),SlotSet("date", None)]
            if len(r)!=0:
                for dic in r:
                    dispatcher.utter_message("NMC count Details\n Digital Count is {}\n Physical Count is {}\n Skinny Count is {}\n Digital Skinny Count is {}\n".format(dic["digitalCount"], dic["physicalCount"], dic["skinnyCount"], dic["digSkinnyCount"]))
                    totalCount = (dic["digitalCount"] + dic["physicalCount"]+ dic["skinnyCount"]+ dic["digSkinnyCount"])/100
                    dispatcher.utter_message("NMC Statistics in percentage % \n Digital Count is {}\n Physical Count is {}\n Skinny Count is {}\n Digital Skinny Count is {}\n".format(round(dic["digitalCount"]/totalCount,2), round(dic["physicalCount"]/totalCount,2), round(dic["skinnyCount"]/totalCount,2), round(dic["digSkinnyCount"]/totalCount,2)))
            else:
                dispatcher.utter_message("No Results Found")
                return [SlotSet("datetimerange", None),SlotSet("daterange", None),SlotSet("date", None)]
            
            return [SlotSet("datetimerange", None),SlotSet("daterange", None),SlotSet("date", None)]

        except Exception as e:
            dispatcher.utter_message("Unable to fetch the results.")
            return [SlotSet("datetimerange", None),SlotSet("daterange", None),SlotSet("date", None)]



class actionAssignmentGroup(Action):

    def name(self) -> Text:
         return "action_assignmentGroup"
    def run(self, dispatcher: CollectingDispatcher,
            tracker: Tracker,
            domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        import requests
        import time

        group_num=tracker.get_slot('group_num')
        state=tracker.get_slot('state')
        sctask_auth_key=config_resp['SCTASK_APIKEY']
        print(state)
        if state == 'open':
            stateValue = 1
            print(stateValue)
        elif state == 'pending':
            stateValue = -5
        else:
            stateValue = 2


        url1 = config_resp['ASSIGNMENT_GROUP_ENDPOINT']
        url2 ='={}&state={}&sysparm_display_value=all'.format(group_num,stateValue)
        url = url1 + url2


        headers = {
            'Authorization': sctask_auth_key,
            'Content-Type': 'application/json',
            }
        try:
                response = requests.request("GET", url, headers=headers)
                if response.status_code == 200:
                    sctaskList =[]
                    line_no = 0
                    t = time.localtime()
                    timestamp = time.strftime('%m-%d-%Y_%H%M%S', t)
                    sctaskfile=("sctaskassignment_"+timestamp+".csv")
                    file = open(sctaskfile,"w",newline="")
                    sfile=csv.writer(file)
                    sfile.writerow(['SCTASK #', 'Status', 'REQ #','RITM #', 'Assigned To','Created dateTime', 'Updated dateTime', 'Closed dateTime','Assignment_group','Priority','short_description'])
                    for item in range(0,len(response.json()['result'])):
                        sctask_number = response.json()["result"][item]["number"]['display_value']
                        sctask_status = response.json()["result"][item]["state"]
                        sys_created_on = response.json()["result"][item]["sys_created_on"]['display_value']
                        sys_updated_on = response.json()["result"][item]["sys_updated_on"]['display_value']
                        closed_at = response.json()["result"][item]["closed_at"]['display_value']
                        priority = response.json()["result"][item]["priority"]['display_value']
                        #work_notes = response.json()["result"][item]["work_notes"]['display_value']
                        short_description = response.json()["result"][item]["short_description"]['display_value']
                        ritm = response.json()["result"][item]["request_item"]["display_value"]
                        req = response.json()["result"][item]["request"]["display_value"]
                        assigned_to = response.json()["result"][item]["assigned_to"]["display_value"]

                        sctaskList.extend((sctask_number,state,req,ritm,assigned_to,sys_created_on,sys_updated_on,closed_at,group_num,priority,short_description))
                        sfile.writerow(sctaskList)
                        sctaskList = []                        
                        line_no = line_no + 1

                    file.close()
                    with open(sctaskfile) as f:
                      content = f.read()
                    data = open(sctaskfile, "rb").read()
                    encoded = (base64.b64encode(data))
                    message={"payload":"Sctaskdata","data":encoded}
                    dispatcher.utter_message(text="Please click here to download report:",json_message=message)
                    os.remove(sctaskfile)
                    return[AllSlotsReset()]
                else:
                    dispatcher.utter_message("Bad response")
                    print("Bad response")
                    return[AllSlotsReset()]

        except Exception as e:
                dispatcher.utter_message('Something went wrong Please try Again')
               
                return[AllSlotsReset()]

class actionChangeTask(Action):

    def name(self) -> Text:
         return "action_changetask"
    def run(self, dispatcher: CollectingDispatcher,
            tracker: Tracker,
            domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        import requests
        import time

        group_num=tracker.get_slot('group_num')
        state=tracker.get_slot('state')
        start_date=tracker.get_slot('start_date')
        end_date=tracker.get_slot('end_date')
        sctask_auth_key=config_resp['SCTASK_APIKEY']
        print(state)
        if state == 'in progress':
            stateValue = 1
            print(stateValue)
        elif state == 'pending':
            stateValue = -5
        elif state == 'closeds':
            stateValue = 3
        elif state == 'closedu':
            stateValue = 6
        elif state == 'closedc':
            stateValue = 7
        url1 = config_resp['CHANGE_TASK_ENDPOINT']
        url2 ='assignment_group={}&state={}&sysparm_display_value=all'.format(group_num,stateValue)
        url = url1 + url2
        headers = {
            'Authorization': sctask_auth_key,
            'Content-Type': 'application/json',
            }
        try:
                response = requests.request("GET", url, headers=headers)
                if response.status_code == 200:
                    print("im here")
                    flag=""
                    #print("printing response of json",response.json(),len(response.json()['result']))
                    sctaskList =[]
                    t = time.localtime()
                    timestamp = time.strftime('%m-%d-%Y_%H%M%S', t)
                    sctaskfile=("CtaskReport_"+timestamp+".csv")
                    file = open(sctaskfile,"w",newline="")
                    sfile=csv.writer(file)
                    sfile.writerow(["change_task","CtaskNum","state","assignment_group","due_date","assigned_to","expected_start_date","opened_by","short_description"])
                    for item in range(0,len(response.json()['result'])):
                        change_task= (response.json())["result"][item]["change_request"]['display_value']
                        CtaskNum = response.json()["result"][item]["number"]['display_value']
                        state = response.json()["result"][item]["state"]['display_value']
                        assignment_group = response.json()["result"][item]["assignment_group"]['display_value']
                        due_date = response.json()["result"][item]["due_date"]['display_value']
                        assigned_to = response.json()["result"][item]["assigned_to"]['display_value']
                        expected_start = response.json()["result"][item]["expected_start"]['display_value']
                        opened_by = response.json()["result"][item]["opened_by"]['display_value']
                        short_description= response.json()["result"][item]["short_description"]['display_value']
                        datetime_str = expected_start
                        #datetime_str=response.json()["result"][item]["opened_at"]['display_value']
                        # start_date="2021-04-01 21:00:00"
                        # end_date="2021-05-01 21:00:00"
                        str_datetime_object = datetime.strptime(start_date, '%Y-%m-%d %H:%M:%S')
                        end_datetime_object = datetime.strptime(end_date, '%Y-%m-%d %H:%M:%S')
                        exp_datetime_object = datetime.strptime(datetime_str, '%Y-%m-%d %H:%M:%S')
                        print(str_datetime_object,exp_datetime_object,end_datetime_object)
                        #print((change_task,CtaskNum,state,assignment_group,due_date,assigned_to,expected_start,opened_by,short_description))
                        if str_datetime_object<=exp_datetime_object<= end_datetime_object:
                            sctaskList.extend((change_task,CtaskNum,state,assignment_group,due_date,assigned_to,expected_start,opened_by,short_description))
                            #print(sctaskList)
                            print(len(sctaskList))
                            sfile.writerow(sctaskList)
                            flag="true"
                        sctaskList = []                        
                    file.close()
                    with open(sctaskfile) as f:
                      content = f.read()
                    data = open(sctaskfile, "rb").read()
                    encoded = (base64.b64encode(data))
                    message={"payload":"ctaskdata","data":encoded}
                    if flag=="true":
                     dispatcher.utter_message(text="Please click here to download report:",json_message=message)
                    else:
                     dispatcher.utter_message("Couldn't fetch any change task tickets in this datetimerange ") 
                    #os.remove(sctaskfile)
                    return[AllSlotsReset()]
                else:
                    dispatcher.utter_message("Bad response")
                    print("Bad response")
                    return[AllSlotsReset()]

        except Exception as e:
                dispatcher.utter_message('Something went wrong Please try Again')
                print(e)
               
                return[AllSlotsReset()]


class ActionAssignmentForm(FormAction):
    def name(self) -> Text:
        return "Action_assignment_grp"
    @staticmethod
    def required_slots(tracker: Tracker)-> List[Text]:
        return{"group_num"}
    def slot_mappings(self) -> Dict[Text, Union[Dict, List[Dict]]]:
    


     return {
        
        "group_num": [self.from_text()]
      }


    def submit(
    self,
    dispatcher: CollectingDispatcher,
    tracker: Tracker,
    domain: Dict[Text, Any],
        ) -> List[Dict]:
        
        return []

class actionSctaskticket(Action):

    def name(self) -> Text:
         return "action_sctask_tickets"
    def run(self, dispatcher: CollectingDispatcher,
            tracker: Tracker,
            domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:

        import requests
        import time

        report_state = tracker.get_slot('sctask_report_state')
        user_id = tracker.get_slot('sctask_report_id')
        sctask_auth_key=config_resp['SCTASK_APIKEY']

        if report_state == 'closed':
            stateValue = 3
        if report_state == 'inprogress':
            stateValue = 2
        if report_state == 'pending':
            stateValue = '-5'
        if report_state == 'open':
            stateValue = 1

        if user_id == 'me':
          user_id = tracker.sender_id

        print(report_state,user_id)

        url1 = config_resp['SCTASK_CLOSE_API']
        if report_state == 'closed':
          url2 = 'sysparm_display_value=all&closed_by={}&state={}'.format(user_id,stateValue)
        else:
          url2 = 'sysparm_display_value=all&assigned_to={}&state={}'.format(user_id,stateValue)
        url = url1 + url2

        print(url)
        headers = {
            'Authorization': sctask_auth_key,
            'Content-Type': 'application/json',
            }
        try:
                response = requests.request("GET", url, headers=headers)
                if response.status_code == 200:
                    ticket = []
                    short_desc = []
                    closed_by = []
                    closed_notes = []
                    assigned_to = []
                    worker_note = []
                    req = []
                    ritm = []
                    opened_by = []
                    closed_at = []
                    assignment_group = []
                    desc = []

                    report_lst = []
                    line_no = 0

                    t = time.localtime()
                    timestamp = time.strftime('%m-%d-%Y_%H%M%S', t)
                    sctaskfile=("sctaskReport_"+timestamp+".csv")
                    file = open(sctaskfile,"w",newline="")
                    sfile=csv.writer(file)
                    sfile.writerow(['Ticket', 'Short_desc', 'Closed_by', 'Closed_notes', 'Assigned_to','Worker_note','REQ #','RITM #','Opened_by','Closed_at','Assignment_group','Desc'])
                    for item in range(0,len(response.json()['result'])):
                        ticket = response.json()["result"][item]["number"]["value"].replace(',','')
                        short_desc = response.json()["result"][item]["short_description"]["value"].replace(',','')
                        closed_by = response.json()["result"][item]["closed_by"]["display_value"].replace(',','')
                        closed_notes = response.json()["result"][item]["close_notes"]["value"].replace(',','')
                        assigned_to = response.json()["result"][item]["assigned_to"]["display_value"].replace(',','')
                        worker_note = response.json()["result"][item]["comments_and_work_notes"]["display_value"].replace(',','')
                        req = response.json()["result"][item]["parent"]["display_value"].replace(',','')
                        ritm = response.json()["result"][item]["request"]["display_value"].replace(',','')
                        opened_by = response.json()["result"][item]["opened_by"]["display_value"].replace(',','')
                        closed_at = response.json()["result"][item]["closed_at"]["display_value"].replace(',','')
                        assignment_group = response.json()["result"][item]["assignment_group"]["display_value"].replace(',','')
                        desc = response.json()["result"][item]["description"]["value"].replace('\n','') + ','

                        report_lst.extend((ticket,short_desc,closed_by,closed_notes,assigned_to,worker_note,req,ritm,opened_by,closed_at,assignment_group,desc))

                        sfile.writerow(report_lst)
                        report_lst = []
                        line_no = line_no + 1

                    file.close()
                    with open(sctaskfile) as f:
                      content = f.read()
                    data = open(sctaskfile, "rb").read()
                    encoded = (base64.b64encode(data))
                    message={"payload":"Sctaskdata","data":encoded}
                    dispatcher.utter_message(text="Please click here to download report:",json_message=message)
                    os.remove(sctaskfile)

                else:
                    dispatcher.utter_message("Bad response")
                    print("Bad response")
                    return[AllSlotsReset()]

        except Exception as e:
                dispatcher.utter_message('Something went wrong Please try Again',e)

class Actionsearchformsctask(FormAction):
    def name(self) -> Text:
        return "sctask_closed_assignee"
    @staticmethod
    def required_slots(tracker: Tracker)-> List[Text]:
        return{"sctask_report_id"}
    def slot_mappings(self) -> Dict[Text, Union[Dict, List[Dict]]]:
    

     return {
        
        "sctask_report_id": [self.from_text()]
      }

    def submit(
    self,
    dispatcher: CollectingDispatcher,
    tracker: Tracker,
    domain: Dict[Text, Any],
        ) -> List[Dict]:
        
        return []


class ActionChangeTaskform(FormAction):
    def name(self) -> Text:
        return "change_task_form"
    @staticmethod
    def required_slots(tracker: Tracker)-> List[Text]:
        return["change_ticket","work_notes","close_notes"]
    
    def slot_mappings(self) -> Dict[Text, Union[Dict, List[Dict]]]:
    

     return {
        
        "change_ticket": [self.from_text()],"work_notes":[self.from_text()],"close_notes":[self.from_text()]
      }
    def submit(
    self,
    dispatcher: CollectingDispatcher,
    tracker: Tracker,
    domain: Dict[Text, Any],
        ) -> List[Dict]:
        
        return []
# fetching IDCMS NMC details 

class ActionDockerHealth(Action):

     def name(self) -> Text:
         return "action_docker_health"

     def run(self, dispatcher: CollectingDispatcher,
             tracker: Tracker,
             domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        import requests

        docker_service=tracker.get_slot('docker_service')
        docker_env=tracker.get_slot('docker_env')

        try:

         token = config_resp['STACKSTORM_TOKEN']
         base_url= config_resp['STACKSTORM_EXECUTION_API']
         headers={'St2-Api-Key':token,'content-type':'application/json'}
         #print("imhereeee")
         data = {
         "action": "smartalert.HealthStatusOfDockerService",
         "parameters": {
         "AlertID":'1234',
         "ComponentName":'Docker',
         "Environment":docker_env,
         "Host": 'hostname',
         "ServiceName":docker_service
           }
         }
         data=json.dumps(data)
         # sending post request and saving response as response object 
         r = requests.post(url = base_url, data = data,headers=headers, verify = cert)
         #print(r.json())
         unique_id=r.json()['id']
         thresold=0
         #print(unique_id)
         res=""
         apiurl=base_url+'/'+'{}'.format(unique_id)
         while thresold<=40:
            response=requests.get(apiurl,verify = cert,headers=headers)
            print(response.json()['status'])
            if response.json()['status'] in ["succeeded"]:
                    print(response.json()['result']['output']['Result']['Output'])
                    res=res+("<b>Component Name: </b>{}<br>".format(response.json()['result']['output']['Result']['Output']['ComponentName']))
                    res=res+("<b>Service: </b>{}<br>".format(response.json()['result']['output']['Result']['Output']['ServiceName']))
                    res=res+("<b>Status: </b>{}<br>".format(response.json()['result']['output']['Result']['Output']['Details']))
                    res=res+("<b>Exception: </b>{}<br>".format(response.json()['result']['output']['Result']['Exception']))
                    dispatcher.utter_message(res)
                    break 
            time.sleep(2)
            print(thresold)
            thresold=thresold+2
         if thresold>=40:
          dispatcher.utter_message("Something went wrong ,please try again")
        except Exception as e:
          dispatcher.utter_message("Something went wrong,Please try again")   
        return [AllSlotsReset()]

class Actiondockerser(FormAction):
    def name(self) -> Text:
        return "docker_service_name"
    @staticmethod
    def required_slots(tracker: Tracker)-> List[Text]:
        return{"docker_service"}
    def slot_mappings(self) -> Dict[Text, Union[Dict, List[Dict]]]:
    

     return {
        
        "docker_service": [self.from_text()]
      }

    def submit(
    self,
    dispatcher: CollectingDispatcher,
    tracker: Tracker,
    domain: Dict[Text, Any],
        ) -> List[Dict]:
        
        return []

class Actionfeedback(Action):

     def name(self) -> Text:
         return "action_feedback"

     def run(self, dispatcher: CollectingDispatcher,
             tracker: Tracker,
             domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        import requests

        feedback_txt=tracker.get_slot('feedback_txt')

        #new_changes
        try:
         
         #AQCmdiCqeHNoWz2SXCPYT7RraN9rBNUymtGrfeqRg2Zdqs74VPcK5QMQMuuBoXAAjxnWtT7qmmapw4kmehWfaMdm3QucqXhmK8Q5H9hsx3AuBirejZLSi8Oxw2Bqx7fKj8waez/1myyxGdTn45mEzjOkwOqxeYHjke7VjAUPc6/w1qF9wZHWeT9Gk+usEJembwtFkrvGFcAyLUKZHUObmlJVfmP/XJIwH6+equc3quhCCTuv+GU2oKy+0+0as8NAc0WRIEh/mwsLXrNItLbxg+mkXSEG+Xl/HcxN37M8cwOr46aU1YXaujVs01rmsR9Gf7kOo8E+DViYqe4OuaaBJ37Ql67FFTUaY5n7uX4m3d5wDlm5TvCGh9Icw3hgZ0xO9Zo3Td+eu0RA6RSPOsZDx5MD0GtTYxKaakR9pkvS5VYJmZ8uzWr+t6rMofWDk8r7MwQ126kid4PWDParwxukSOCq4UTESNoOlCTV1UQRJKdLzars0/J0+p1k/YYP36R4XElKGXQdN1YXFwR1MqwBjIpsmEX9TezK4sMXLSWmDAQt9w==
         mongouriaud="mongodb://srctsyddrw:pgukrw%40xtphh@va33tlpmdb004.wellpoint.com:37043/SYDNEYDB?ssl=true&appName=smartBuddy"
         client = pymongo.MongoClient(mongouriaud)
         db=client['SYDNEYDB']
         #db.list_collection_names()
         collectionaud=db['smartchat_audit']

         insertquery={"userID":"","startTime":"","endTime":"","usecase":"","status":"","exceptions":"","feedbackFlag":"","feedback":""}
         val = collectionaud.insert_one(insertquery)

         mongodocid=str(val.inserted_id)
         searchquery={"_id" : val.inserted_id}
         collectionaud.update_one(searchquery,{ "$set": { "userID": tracker.sender_id,"endTime": (datetime.now()) ,"feedbackFlag": feedback_txt  } })

        except Exception as e:
          dispatcher.utter_message("Something went wrong,Please try again", e)   
        return [AllSlotsReset()]

class ActionfileSysChk(Action):

     def name(self) -> Text:
         return "action_fileSysCheck"

     def run(self, dispatcher: CollectingDispatcher,
             tracker: Tracker,
             domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        import requests

        fileSys_comp=tracker.get_slot('fileSys_comp')
        fileSys_env=tracker.get_slot('fileSys_env')
        fileSys_mount=tracker.get_slot('fileSys_mountOn')

        try:

         token = "MGJlYTkxNWEwMDA0ZTBlZjdmMzhiYjRkNmM4NTEwMTlkYTUxY2FkMWY2MjhmZDJhOTAyMzZlOTc1Zjc2OGM2NQ" #config_resp['STACKSTORM_TOKEN']
         base_url= "https://uat-interlock.anthem.com/stackstorm/cofactory/api/v1/executions" #config_resp['STACKSTORM_EXECUTION_API']
         headers={'St2-Api-Key':token,'content-type':'application/json'}
         #print("imhereeee")
         data = {
         "action": "smartalert.CurrentFileSystemUsage",
         "parameters": {
         "UserName": "usernameToConnectHost",
         "Password": "PasswrodToConnectHost",
         "AlertID": "1234",
         "ComponentName": fileSys_comp,
         "Environment":fileSys_env,
         "Host": 'hostname',
         "MountedOn": fileSys_mount,
         "FilsystemUtilization": "90"
           }
         }
         data=json.dumps(data)
         # sending post request and saving response as response object 
         r = requests.post(url = base_url, data = data,headers=headers, verify = cert)
         #print(r.json())
         unique_id=r.json()['id']
         thresold=0
         print(unique_id)
         res=""
         apiurl=base_url+'/'+'{}'.format(unique_id)
         while thresold<=30:
            response=requests.get(apiurl,verify = cert,headers=headers)
            print(response.json()['status'])
            if response.json()['status'] in ["succeeded"]:
                    print(response.json())
            #         print(response.json()['result']['output']['Result']['Output'])
            #         res=res+("<b>Component Name: </b>{}<br>".format(response.json()['result']['output']['Result']['Output']['ComponentName']))
            #         res=res+("<b>Service: </b>{}<br>".format(response.json()['result']['output']['Result']['Output']['ServiceName']))
            #         res=res+("<b>Status: </b>{}<br>".format(response.json()['result']['output']['Result']['Output']['Details']))
            #         res=res+("<b>Exception: </b>{}<br>".format(response.json()['result']['output']['Result']['Exception']))
            #         dispatcher.utter_message(res)
                    break 
            time.sleep(2)
            print(thresold)
            thresold=thresold+2
         if thresold>=30:
          dispatcher.utter_message("Something went wrong ,please try again")
        except Exception as e:
          dispatcher.utter_message("Something went wrong,Please try again")   
        return [AllSlotsReset()]

class ActionfileSysMount(FormAction):
    def name(self) -> Text:
        return "fileSys_mount_name"
    @staticmethod
    def required_slots(tracker: Tracker)-> List[Text]:
        return{"fileSys_mountOn"}
    def slot_mappings(self) -> Dict[Text, Union[Dict, List[Dict]]]:
    

     return {
        
        "fileSys_mountOn": [self.from_text()]
      }

    def submit(
    self,
    dispatcher: CollectingDispatcher,
    tracker: Tracker,
    domain: Dict[Text, Any],
        ) -> List[Dict]:
        
        return []

class ActionfileSysComp(FormAction):
    def name(self) -> Text:
        return "fileSys_Comp_name"
    @staticmethod
    def required_slots(tracker: Tracker)-> List[Text]:
        return{"fileSys_comp"}
    def slot_mappings(self) -> Dict[Text, Union[Dict, List[Dict]]]:
    

     return {
        
        "fileSys_comp": [self.from_text()]
      }

    def submit(
    self,
    dispatcher: CollectingDispatcher,
    tracker: Tracker,
    domain: Dict[Text, Any],
        ) -> List[Dict]:
        
        return []

class ActionAssetTool(Action):

     def name(self) -> Text:
         return "action_AssetTool"

     def run(self, dispatcher: CollectingDispatcher,
             tracker: Tracker,
             domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        import requests

        asset_server=tracker.get_slot('assetServer')
        asset_env=tracker.get_slot('assetEnv')

        Asset_API= config_resp['ASSERT_API_SINGLE']

        payload = {
           'serverName': asset_server,
           'ipAddress': "30.128.210.117",
           'environment': asset_env,
           'function': "API-EDGE"
           }

        payload=json.dumps(payload)

        headers = {
            'token': config_resp['ASSERT_TOKEN'],
            'Content-Type': 'application/json',
           }
        
        res = ""
        try:
           response = requests.request("POST", Asset_API, headers=headers, data = payload, verify = cert)
           r=response.json()
           if response.status_code==200:
            res=res+("<b>Server Name: </b>{}<br>".format(response.json()[0]['serverName']))
            res=res+("<b>IP Address: </b>{}<br>".format(response.json()[0]['ipAddress']))
            res=res+("<b>Function: </b>{}<br>".format(response.json()[0]['function']))
            res=res+("<b>Sub Type: </b>{}<br>".format(response.json()[0]['subType']))
            res=res+("<b>SME: </b>{}<br>".format(response.json()[0]['sme']))
            res=res+("<b>OS Ver: </b>{}<br>".format(response.json()[0]['os']))
            dispatcher.utter_message(res)
           
        except Exception as e:
          dispatcher.utter_message('Something went wrong Please try Again')
          
        return [AllSlotsReset()]

class ActionAssetServer(FormAction):
    def name(self) -> Text:
        return "Asset_server_name"
    @staticmethod
    def required_slots(tracker: Tracker)-> List[Text]:
        return{"assetServer"}
    def slot_mappings(self) -> Dict[Text, Union[Dict, List[Dict]]]:
    

     return {
        
        "assetServer": [self.from_text()]
      }

    def submit(
    self,
    dispatcher: CollectingDispatcher,
    tracker: Tracker,
    domain: Dict[Text, Any],
        ) -> List[Dict]:
        
        return []

class ActionAssetToolBulk(Action):

     def name(self) -> Text:
         return "action_AssetToolBulk"

     def run(self, dispatcher: CollectingDispatcher,
             tracker: Tracker,
             domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        import requests

        asset_server=tracker.get_slot('assetServerBulk')
        var = asset_server.split(",")
        value = []
        for item in var:
          value.append("'" + item.strip() + "'")
        asset_server = value


        Asset_API= config_resp['ASSERT_API_BULK']

        payload = {
           'serverName': asset_server,
           }

        payload=json.dumps(payload)

        headers = {
            'token': config_resp['ASSERT_TOKEN'],
            'Content-Type': 'application/json',
           }
        
        try:
           response = requests.request("POST", Asset_API, headers=headers, data = payload, verify = cert)
           r=response.json()
           res = ""
           if response.status_code==200:

            for item in response.json():
              res=res+("<b>Server Name: </b>{}<br>".format(item['serverName']))
              res=res+("<b>IP Address: </b>{}<br>".format(item['ipAddress']))
              res=res+("<b>Environment: </b>{}<br>".format(item['environment']))
              res=res+("<b>Function: </b>{}<br>".format(item['function']))
              res=res+("<b>Sub Type: </b>{}<br>".format(item['subType']))
              res=res+("<b>SME: </b>{}<br>".format(item['sme']))
              res=res+("<b>OS Ver: </b>{}<br><br>".format(item['os']))

            dispatcher.utter_message(res)
           
        except Exception as e:
          dispatcher.utter_message('Something went wrong Please try Again')
          
        return [AllSlotsReset()]

class ActionAssetServer(FormAction):
    def name(self) -> Text:
        return "Asset_server_nameBulk"
    @staticmethod
    def required_slots(tracker: Tracker)-> List[Text]:
        return{"assetServerBulk"}
    def slot_mappings(self) -> Dict[Text, Union[Dict, List[Dict]]]:
    

     return {
        
        "assetServerBulk": [self.from_text()]
      }

    def submit(
    self,
    dispatcher: CollectingDispatcher,
    tracker: Tracker,
    domain: Dict[Text, Any],
        ) -> List[Dict]:
        
        return []        