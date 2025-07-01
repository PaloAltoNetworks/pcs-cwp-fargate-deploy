import json
import sys
import re

from urllib3 import Timeout, PoolManager
from time import sleep

PATTERNS = [
    r'[A-Za-z0-9+\/=]{80,}', #Long base64 strings
    r'[A-Za-z0-9+\/]{27}=', #Secret key pattern
    r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}' #UUID Pattern   
]

class RequestError(Exception):
    pass


# Function to be used to replace sensitive information delivered through logs
def replace_sensitive_data(text, placeholder="****"):
    """Replace Senitive date to be output"""

    for pattern in PATTERNS:
        results = re.findall(pattern, text)
        if results:
            for result in results:
                new_string = f"{result[:4]}{placeholder}"
                text = text.replace(result, new_string)

    return text


class PrismaAPI(object):
    def __init__(self, 
        prisma_api_endpoint: str,
        compute_api_endpoint: str,
        username: str,
        password: str,
        limit=50,
        time_sleep=5,
        connect_timeout=5,
        read_timeout=20,
        debug=False
    ):
        self.prisma_api_endpoint = prisma_api_endpoint
        self.compute_api_endpoint = compute_api_endpoint
        self.username = username
        self.password = password
        self.limit = limit
        self.time_sleep = time_sleep
        self.debug = debug
        timeout = Timeout(connect=connect_timeout, read=read_timeout)
        self.http = PoolManager(timeout=timeout)

        self.headers = {"Content-Type": "application/json"}

        token_body = {
            "username": self.username,
            "password": self.password
        }

        if not self.prisma_api_endpoint:
            if not self.compute_api_endpoint:   
                print("If PRISMA_API_ENDPOINT is not set, then COMPUTE_API_ENDPOINT is required.")
                sys.exit(1)
            else:
                # Check for console connectivity
                self.has_connectivity()

                # Retrieve Compute Console token
                compute_token = json.loads(self.http_request(self.compute_api_endpoint, "/api/v1/authenticate", token_body))["token"]
                self.headers["Authorization"] = f"Bearer {compute_token}"

        else:
            # Retrieve Prisma Cloud token
            prisma_token = json.loads(self.http_request(self.prisma_api_endpoint, "/login", token_body))["token"]
            self.headers["X-Redlock-Auth"] = prisma_token

            if not self.compute_api_endpoint:
                # Get Compute API endpoint
                self.compute_api_endpoint = json.loads(self.http_request(self.prisma_api_endpoint, "/meta_info", method="GET"))["twistlockUrl"]


    def has_connectivity(self):
        response = self.http.request("GET",f"{self.compute_api_endpoint}/api/v1/_ping")
        if response.status == 200:
            print(f"Connection to the endpoint {self.compute_api_endpoint} succedded.")
        else:
            print(f"Connection to the endpoint {self.compute_api_endpoint} failed.")
            sys.exit(1)


    def http_request(self, api_endpoint, path, body={}, method="POST", skip_error=False):
        if self.debug: print(f"Making the following request:\n    URL: {api_endpoint}\n    Path: {path}\n    Method: {method}\n")
        response = self.http.request(method, f"{api_endpoint}{path}", headers=self.headers, body=json.dumps(body))

        if response.status == 200:
            return response.data
        
        if response.status in (401, 500) and path not in ("/login", "/api/v1/authenticate"):
            token_body = {
                "username": self.username,
                "password": self.password
            }

            if "X-Redlock-Auth" in self.headers:
                token = json.loads(self.http_request(self.prisma_api_endpoint, "/login", token_body))["token"]
                self.headers["X-Redlock-Auth"] = token

            elif "Authorization" in self.headers:
                token = json.loads(self.http_request(self.compute_api_endpoint, "/api/v1/authenticate", token_body))["token"]
                self.headers["Authorization"] = f"Bearer {token}"
                
            return self.http_request(api_endpoint, path, body, method, skip_error)
        
        if response.status == 429:
            sleep(self.time_sleep)
            return self.http_request(api_endpoint, path, body, method, skip_error)

        #Message to print
        msg = f"Error making request to {api_endpoint}{path}. Method: {method}. Body: {body}. Error message: {response.data}. Status code: {response.status}"
        
        if not skip_error:
            raise RequestError(replace_sensitive_data(msg))
        
        if self.debug: print(replace_sensitive_data(msg))
        return "{}"


    def compute_request(self, path, body={}, method="POST", skip_error=False, format="json"):
        if format == "json":
            return json.loads(self.http_request(self.compute_api_endpoint, path, body, method, skip_error))

        return self.http_request(self.compute_api_endpoint, path, body, method, skip_error)


    def prisma_request(self, path, body={}, method="POST", skip_error=False, format="json"):
        if format == "json":
            return json.loads(self.http_request(self.prisma_api_endpoint, path, body, method, skip_error))
        
        return self.http_request(self.prisma_api_endpoint, path, body, method, skip_error)


    def get_all_compute_resources(
            self, 
            path, 
            parameters = "", 
            skip_error=False, 
            max_items=0, 
            limit=0, 
            breakpoints={}
        ):
        offset = 0
        response = "first_response"
        data = []
        base_path = f"{path}?limit={limit}" if limit else f"{path}?limit={self.limit}"
        if parameters: base_path = f"{base_path}&{parameters}"

        while response:
            stop = False
            full_path = f"{base_path}&offset={offset}" 
            response = self.compute_request(full_path, method="GET", skip_error=skip_error)
            if response:
                data += response
                offset = offset + self.limit if not limit else offset + limit
            
                if breakpoints:
                    last_item = response[-1]
                    for key, value in breakpoints.items():
                        if key in last_item:
                            if last_item[key] == value:
                                stop = True
                                break
            
            if (max_items and offset >= max_items) or stop: break

        if self.debug: print(f"Total data retrieved from Compute Console: {len(data)}. Path: {path}\n")
        return data


    def get_all_cspm_resources(
            self, 
            path, 
            parameters = "", 
            body = {},
            method = "POST", 
            skip_error=False, 
            max_items=0,
            data_path = [], 
            page_token_path = [], 
            token_in_headers = True, 
            page_token_key="nextPageToken", 
        ):
        
        page_token = "first_response"
        data = []
        base_path = path

        def extract_data_from_dict(data, keys: list):
            if len(keys) == 1:
                if keys[0] in data: 
                    return data[keys[0]]
       
            else:
                if keys[0] in data: 
                    return extract_data_from_dict(data[keys[0]], keys[1:])
            return []

        if parameters: base_path = f"{path}?{parameters}"

        while page_token:
            if page_token != "first_response":
                if token_in_headers:
                    base_path = f"{path}?page_token={page_token}"
                    if parameters: base_path = f"{base_path}&{parameters}"
                else:
                    body[page_token_key] = page_token
            
            response = self.prisma_request(base_path, body=body, method=method, skip_error=skip_error)
            
            if response:
                data += extract_data_from_dict(response, data_path)
                page_token = extract_data_from_dict(response, page_token_path)

            if max_items and len(data) >= max_items: break

        if self.debug: print(f"Total data retrieved from Prisma Console: {len(data)}. Path: {path}\n")
        return data
