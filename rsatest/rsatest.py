'''
Replace RSA_AM_NAME_HERE with your RSA Authentication Manager Hostname/IP
Replace YOUR_ACCESS_KEY_HERE with your API Access Key
Replace YOUR_CLIENT_ID_HERE with the RSA AM agent name created for testing
'''

import requests
import uuid
import urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

auth_manager_url = "https://RSA_AM_NAME_HERE:5555/mfa/v1_1/authn/initialize"
access_key = "YOUR_ACCESS_KEY_HERE"
client_id = "YOUR_CLIENT_ID_HERE"

username = input("Enter your username:")
otp_token = input("Enter your OTP:")
message_id = str(uuid.uuid4())

payload = {
	"clientId": client_id,
	"subjectName": username,
	"subjectCredentials": [
		{
			"methodId": "SECURID",
			"collectedInputs": [
				{
					"name": "SECURID",
					"value": otp_token
				}
			]
		}
	],
	"context": {
		"authnAttemptId": "",
		"messageId": message_id,
		"inResponseTo": ""
	}
}

headers = {
	"Content-Type": "application/json",
	"client-key": access_key
}

response = requests.post(auth_manager_url, json=payload, headers=headers, verify=False)
output_response = response.json()
attemptResponse = output_response["attemptResponseCode"]

if attemptResponse == "SUCCESS":
	print("OTP verification successful!:", output_response)
else:
	print("OTP verification failed:", response.status_code, response.text)
