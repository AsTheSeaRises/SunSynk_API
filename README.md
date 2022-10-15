# SunSynk API 
The purpose of this Python code is to retrieve the plant id and current power generation data from a Sunsynk inverter. Using this information you can then choose to take actions based on this data - e.g. trigger IoT devices, lights, notifications, adjust inverter settings etc.

# Requirements
SunSynk account created on https://sunsynk.net/ site, and an SunSynk inverter that has internet connectivity using the wifi enable data logger. (https://www.sunsynk.org/remote-monitoring)

# Steps
1) Confirm connectivity to inverter from wifi or internet.

3) Edit the python file to include your email and password at line 15 and 16. This is the same username/password used to access the sunsynk.net website when retrieving your inverter details from the mobile app.

my_user_email = ('<ENTER YOUR EMAIL ADDRESS>')
  
my_user_password = ('<ENTER YOUR PASSWORD>')
