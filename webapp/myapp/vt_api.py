import os
import sys
import time
import json
import requests
import argparse
import hashlib
import html

VT_API_KEY = ""

VT_API_URL = "https://www.virustotal.com/api/v3/"

class VTScanException(Exception):
    pass

class VTScan:
    def __init__(self):
        self.headers = {
            "x-apikey": VT_API_KEY,
            "User-Agent": "vtscan v.1.0",
            "Accept-Encoding": "gzip, deflate",
        }

    def upload(self, malware_path):
        print("upload file: " + malware_path + "...")
        sys.stdout.flush()
        self.malware_path = malware_path
        upload_url = VT_API_URL + "files"
        files = {"file": (os.path.basename(malware_path), open(os.path.abspath(malware_path), "rb"))}
        print("upload to " + upload_url)
        sys.stdout.flush()
        res = requests.post(upload_url, headers=self.headers, files=files)
        if res.status_code == 200:
            result = res.json()
            self.file_id = result.get("data").get("id")
            print(self.file_id)
            print("successfully upload PE file: OK")
            sys.stdout.flush()
        else:
            print("failed to upload PE file :(")
            print("status code: " + str(res.status_code))
            raise VTScanException("Failed to upload PE file")

    def analyse(self):
        print("get info about the results of analysis...")
        sys.stdout.flush()
        analysis_url = VT_API_URL + "analyses/" + self.file_id
        res = requests.get(analysis_url, headers=self.headers)
        if res.status_code == 200:
            result = res.json()
            status = result.get("data").get("attributes").get("status")
            if status == "completed":
                stats = result.get("data").get("attributes").get("stats")
                results = result.get("data").get("attributes").get("results")
                output = "<html><body><p>" 
                output += f"File Name  : {os.path.basename(self.malware_path)}\n"
                output += f"MD5        : {hashlib.md5(open(self.malware_path, 'rb').read()).hexdigest()}\n"
                output += f"SHA-1      : {hashlib.sha1(open(self.malware_path, 'rb').read()).hexdigest()}\n"
                output += f"SHA-256    : {hashlib.sha256(open(self.malware_path, 'rb').read()).hexdigest()}\n"
                output += f"File type  : {results.get('type')}\n"
                output += f"<span style='color: red;'>malicious  : {stats.get('malicious')}\n</span>"
                output += f"<span style='color: orange;'>undetected : {stats.get('undetected')}\n\n</span>"
                for k in results:
                    if results[k].get("category") == "malicious":
                        output += "==================================================\n"
                        output += f"{results[k].get('engine_name')}\n"
                        output += f"version  : {results[k].get('engine_version')}\n"
                        output += f"category : {results[k].get('category')}\n"
                        output += f"<span style='color: red;'> result   : {results[k].get('result')}\n</span>"
                        output += f"method   : {results[k].get('method')}\n"
                        output += f"update   : {results[k].get('engine_update')}\n"
                        output += "==================================================\n\n"
                print("successfully analyse: OK")
                sys.stdout.flush()
                with open("myapp/templates/myapp/result.txt", "w") as output_file:
                    output_file.write(output)
                return output 
            elif status == "queued":
                print("status QUEUED...")
                sys.stdout.flush()
                with open(os.path.abspath(self.malware_path), "rb") as malware_path:
                    b = malware_path.read()
                    hashsum = hashlib.sha256(b).hexdigest()
                    self.info(hashsum)
            else:
                print("Analysis status not completed: " + status)
                raise VTScanException("Analysis status not completed")
        else:
            print("failed to get results of analysis :(")
            print("status code: " + str(res.status_code))
            raise VTScanException("Failed to get results of analysis")

    def run(self, malware_path):
        try:
            self.upload(malware_path)
            self.analyse()
        except VTScanException as e:
            print(str(e))

    def info(self, file_hash):
        print("get file info by ID: " + file_hash)
        sys.stdout.flush()
        info_url = VT_API_URL + "files/" + file_hash
        res = requests.get(info_url, headers=self.headers)
        if res.status_code == 200:
            result = res.json()
            if result.get("data").get("attributes").get("last_analysis_results"):
                stats = result.get("data").get("attributes").get("last_analysis_stats")
                results = result.get("data").get("attributes").get("last_analysis_results")
                output = "<html><body><p>" 
                output += f"File Name  : {os.path.basename(self.malware_path)}\n"
                output += f"MD5        : {hashlib.md5(open(self.malware_path, 'rb').read()).hexdigest()}\n"
                output += f"SHA-1      : {hashlib.sha1(open(self.malware_path, 'rb').read()).hexdigest()}\n"
                output += f"SHA-256    : {hashlib.sha256(open(self.malware_path, 'rb').read()).hexdigest()}\n"
                output += f"File type  : {results.get('type')}\n"
                output += f"<span style='color: red;'>malicious  : {stats.get('malicious')}\n</span>"
                output += f"<span style='color: orange;'>undetected : {stats.get('undetected')}\n\n</span>"
                for k in results:
                    if results[k].get("category") == "malicious":
                        output += "==================================================\n"
                        output += f"{results[k].get('engine_name')}\n"
                        output += f"version  : {results[k].get('engine_version')}\n"
                        output += f"category : {results[k].get('category')}\n"
                        output += f"result   : {results[k].get('result')}\n"
                        output += f"method   : {results[k].get('method')}\n"
                        output += f"update   : {results[k].get('engine_update')}\n"
                        output += "==================================================\n\n"
                output += f"<span style='color: green;'>successfully analyse: OK</span>"
                output += "</p></body></html>" 
                with open("myapp/templates/myapp/result.txt", "w") as output_file:
                    output_file.write(output)
            else:
                print("failed to analyse :(...")
        else:
            print("failed to get information :(")
            print("status code: " + str(res.status_code))
            raise VTScanException("Failed to get information from VirusTotal API")
