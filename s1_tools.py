import json
import requests
import os
import configparser

class SentinelOne:
    API_KEY = ""
    BASE_URL = ""

    @classmethod
    def get_creds(cls):
        config = configparser.ConfigParser()
        if os.path.isfile("localonly.SOCer.config"):
            config.read("localonly.SOCer.config")
        else:
            config.read("SOCer.config")
        cls.API_KEY = config["S1"]["sentinelone_key"]
        cls.BASE_URL = config["S1"]["base_url"]

    @classmethod
    def search_asset(cls, device = None, ip = None):
        cls.get_creds()
        #LOGIN
        api_key = cls.API_KEY
        CONSOLEURL = cls.BASE_URL # Example: https://your.console.net
        headers = {
        "Content-type": "application/json",
        "Authorization": "APIToken " + api_key
        }
        device_request = "//web/api/v2.1/agents" 
        try:      
            if device is not None and device != "": JSON = requests.get(CONSOLEURL + device_request + "?computerName=" + device , headers=headers).json()
            else: JSON = requests.get(CONSOLEURL + device_request + "?externalIp__contains=" + ip , headers=headers).json()
        except Exception as e: return f"S1 Error {e}"
        
        if len(JSON["data"]) == 0:
                return "No Data"
        else:
            computer = JSON["data"][0]
            return_string = f'''Device Name: {computer["computerName"]}
        IP: {computer["externalIp"]}
        Serial Number: {computer["serialNumber"] }
        Last User: {computer["lastLoggedInUserName"]}
        Active Threats: {computer["activeThreats"]}
        Is Active: {computer["isActive"]}
        Is Up to Date: {computer["isUpToDate"]}
        Last Active: {computer["lastActiveDate"]}'''
        return return_string
