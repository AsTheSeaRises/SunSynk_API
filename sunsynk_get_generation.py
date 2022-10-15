# URL background
#  https://pv.inteless.com/oauth/token 
# Your login details are redirected to the authentication URL, which provides your bearer token for future API requests
# 
# https://sunsynk.net/ 
# This is your Login landing page once you have created your account with SynSynk

import sys
import requests
import json
from requests.auth import HTTPBasicAuth


# Enter your username and password that you created on the Sunsynk website.
my_user_email = ('<ENTER YOUR EMAIL ADDRESS>')
my_user_password = ('<ENTER YOUR PASSWORD>')

loginurl = ('https://pv.inteless.com/oauth/token')

# API call to get realtime inverter related information
plant_id_endpoint = ('https://pv.inteless.com/api/v1/plants?page=1&limit=10&name=&status=')

headers = {
    'Content-type':'application/json', 
    'Accept':'application/json'
    }

payload = {
    "username": my_user_email,
    "password": my_user_password,
    "grant_type":"password",
    "client_id":"csp-web"
    }

# This will print your bearer/access token
raw_data = requests.post(loginurl, json=payload, headers=headers).json()

# Your access token extracted from response
my_access_token = raw_data["data"]["access_token"]
the_bearer_token_string = ('Bearer '+ my_access_token)
print('****************************************************')

print('Your access token is: ' + my_access_token)

# Header includes most recent token
headers_and_token = {
    'Content-type':'application/json', 
    'Accept':'application/json',
    'Authorization': the_bearer_token_string
    }

# Get plant id and current generation in Watts
r = requests.get(plant_id_endpoint, headers=headers_and_token)
data_response = r.json()

print('****************************************************')
plant_id_and_pac = data_response['data']['infos']
for d in plant_id_and_pac:
    your_plant_id = d['id']
    your_plant_pac = d['pac']
    current_gen_w = str(your_plant_pac)
    print('Your plant id is: ' + str(your_plant_id))
    print('****************************************************')
    # You can take actions based on the generation amount, e.g. trigger IoT device, SMS, adjust inverter settings like push to grid
    print('Your current power generation is: ' + str(current_gen_w) +'W')


print('****************************************************')
