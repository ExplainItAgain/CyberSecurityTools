
import json
import logging
import configparser

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class InsightVM:
    """Remove Assets from Rapid7 InsightVM

    Usage Ex:
        asset_name = "dpp2s4idev.alsac.stjude.org"
        print(InsightVM.remove_asset(asset_name))
    """
    API_KEY = r""
    BASE_URL = ""

    def __init__(self, asset_name):
        logging.basicConfig(level=logging.INFO,
                            format="[%(asctime)s] %(message)s", datefmt='%H:%M:%S')

        self.__class__._process_name(asset_name)
        logging.info(f"Asset Name: {self.asset_name}")

    @classmethod
    def get_creds(cls):
        config = configparser.ConfigParser()
        try: config.read("localonly.SOCer.config")
        except: config.read("SOCer.config")
        cls.API_KEY = config["R7"]["insightvm_key"]
        cls.BASE_URL = config["R7"]["base_url"]


    @classmethod
    def remove_asset(cls, asset_name):
        """ Accept the asset name and delete the asset """
        logging.basicConfig(level=logging.INFO,
                            format="[%(asctime)s] %(message)s", datefmt='%H:%M:%S')

        cls.get_creds()
        logging.info(f"Base URL: {cls.BASE_URL}")

        cls._process_name(asset_name)
        logging.info(f"Asset Name: {cls.asset_name}")

        cls._get_asset_id()
        logging.info(f"Assets Returned: {cls.ids}")

        return cls._delete_asset()

    @classmethod
    def _process_name(cls, asset_name):
        """Remove inconsistencies from the asset name and validate length"""
        if ".alsac.local" in asset_name:
            asset_name = asset_name.replace(".alsac.local", "")
        elif ".alsac.stjude.org" in asset_name:
            asset_name = asset_name.replace(".alsac.stjude.org", "")

        #Could delete the wrong assets if the name is too short.
        if len(asset_name) < 6:
            raise Exception(f"Asset Name Too Short. Asset Name is: {asset_name}")

        cls.asset_name = asset_name

    @classmethod
    def _get_asset_id(cls):
        """ Return the asset ID using cls.asset_name """
        cls.ids = []
        headers = {  "User-Agent": "Thunder Client (https://www.thunderclient.com)",
                   "Content-Type": "application/json",  "Accept": "application/json;charset=UTF-8",
                     "Authorization": f"Basic {cls.API_KEY}"
            }
        payload = {
            "filters": [
                {"field":"host-name", "lower":"", "operator":"starts-with",
                 "upper":"","value":cls.asset_name}
            ],
            "match": "all"
        }
        response = requests.post(cls.BASE_URL + "/api/3/assets/search?page=0&size=5",
                                 data=json.dumps(payload), headers=headers, verify=False, timeout=10)
        result = json.loads(response.text)
        try:
            result["resources"]
        except:
            logging.warning(f"Invalid results returned. Results: {result}")
            return
        if len(result["resources"]) > 2:
            raise Exception("Too Many Assets Returned: Search was not specific.")
        for resource in result["resources"]:
            cls.ids.append(resource["id"])

    def _delete_asset(cls):
        """ Delete all ids in cls.ids """
        headers = {  "User-Agent":"Thunder Client (https://www.thunderclient.com)",
                   "Content-Type":"application/json",  "Accept":"application/json;charset=UTF-8",
                    "Authorization":f"Basic {cls.API_KEY}"
        }
        payload = ""
        cls.status_codes = []
        for _id in cls.ids:
            response = requests.delete(cls.BASE_URL + f"/api/3/assets/{_id}",
                                       data=payload, headers=headers, verify=False, timeout=10)
            result = json.loads(response.text)
            logging.info(f"Result for {_id}: {result}")
            cls.status_codes.append(response.status_code)
        
        return zip(cls.ids, cls.status_codes)