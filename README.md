# SunSynk API 
The purpose of this Python code is to retrieve the plant id and current power generation data from a Sunsynk inverter. Using this information you can then choose to take actions based on this data - e.g. trigger IoT devices, lights, notifications, adjust inverter settings etc.

# Requirements
SunSynk account created on https://sunsynk.net/ site, and an SunSynk inverter that has internet connectivity using the wifi enable data logger. (https://www.sunsynk.org/remote-monitoring)

# Steps
1) Confirm connectivity to inverter from wifi or internet.

3) From terminal run the Python file with two arguments in the command-line, the first being your Sunsynk.net username/email and the second being your password for this site. These arguments are used programatically to retrieve the bearer token to for API requests.

The command example would be:
```
python3 sunsynk_get_generation.py <my_username/email> <my_password>
```

4) The output by default runs both functions which will display the bearer token, the plant id and the real-time power generation.
