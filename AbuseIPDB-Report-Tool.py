import sys
import time
import requests
import re
import json
import pandas as pd

#<---Globals--->
apiKey = open("myapiKey.txt", "r")
headers = {
    'Accept': 'application/json',
    'Key': apiKey.read()
}

#opens the .cvs of attack categories (referenced on https://www.abuseipdb.com/categories)
df = pd.read_csv("Categories.csv")
df_reset=df.set_index('#')

#<---functions--->
#currently functions are not needed but used to build on top of

#check / confirm the final report:
def checkIP(ip):
    # Defining the api-endpoint
    checkIPStatusURL = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
        }
    response = requests.request(method='GET', url=checkIPStatusURL, headers=headers, params=querystring)
    # Formatted output
    decodedResponse = json.loads(response.text)
    jsondata = json.dumps(decodedResponse, sort_keys=True, indent=4)
    #prints out data
    print(jsondata)

#Report the suspicious IP. takes ip, attackCategories, and comment variables returned from main() input.
#Use after checkIP() to check for any http errors.
def reportIP(ip, comment, attackCategories):
    url = 'https://api.abuseipdb.com/api/v2/report'
    # String holding parameters to pass in json format
    params = {
        'ip': ip,
        'categories': attackCategories,
        'comment': comment
        }
    response = requests.request(method='POST', url=url, headers=headers, params=params)
    # Formatted output
    decodedResponse = json.loads(response.text)
    jsondataReport = json.dumps(decodedResponse, sort_keys=True, indent=4)
    print(jsondataReport)

#main function
def main():
    # Get user input for analysis
    ip = input('Enter IP:')
    request = input('Enter Request:')
    time = input('Enter Time:')
    size = input('Enter Size:')
    client = input('Enter Client:')
    ref = input('Enter Refering URL:')
    #Prints the .csv of Attack Categories
    print(df_reset)
    attackCategories = input('Enter Attack Categories That Apply (1,2,3..etc):')
    comment = 'IP:[' + ip + '] ' + 'Request:[' + request + '] ' + 'Time:[' + time + '] ' + 'Size:[' + size + '] ' + 'Client:[ ' + client + '] ' + 'Referring URL:[' + ref + '] '
    checkIP(ip)
    #Ask user to confirm checkIP() has no errors/high abuse score.
    reportIPAddr,rIP = input('Report this IP? yes/no/exit:')
    if reportIPAddr == 'yes' or rIP == 'Yes' or rIP == 'y' or rIP == 'Y':
        reportIP(ip, comment, attackCategories)
    elif reportIPAddr == 'exit':
        sys.exit()
    else:
        exit = input('press control+c to leave')

#Acess log function/-l. very similar to main() but much for efficiat for reporting IP's.
def accessLog():
    #User pastes raw access log in this input
    accessLogPaste = input('Paste Access log: ')
    #regex script that filters the raw access log for any range ip address.
    regexScriptForIpAddress = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    #filtered ip address
    ip = regexScriptForIpAddress.search(accessLogPaste)[0]
    comment = accessLogPaste
    checkIP(ip)
    #Ask user to confrim checkIP() has no errors/high abuse score.
    reportIPAddr = input('Report this IP? yes/no/exit:')
    if reportIPAddr == 'yes' or rIP == 'Yes' or rIP == 'y' or rIP == 'Y':
        #Prints the .csv of Attack Categories
        print(df_reset)
        attackCategories = input('Enter Attack Categories That Apply (1,2,3..etc):')
        reportIP(ip, comment, attackCategories)
        time.sleep(1)
        exit = input('press control+c to leave')
    elif reportIPAddr == 'exit':
        sys.exit()
    else:
        print('Exiting in 30 seconds...')
        time.sleep(30)
        sys.exit()

def menu():
    print('''
        _   _                 ___ ___ ___  ___     ___                   _      _____         _
       /_\ | |__ _  _ ___ ___|_ _| _ \   \| _ )___| _ \___ _ __  ___ _ _| |_ __|_   _|__  ___| |
      / _ \| '_ \ || (_-</ -_)| ||  _/ |) | _ \___|   / -_) '_ \/ _ \ '_|  _|___|| |/ _ \/ _ \ |
     /_/ \_\_.__/\_,_/__/\___|___|_| |___/|___/   |_|_\___| .__/\___/_|  \__|    |_|\___/\___/_|
                                                          |_|
            - a simple python script to analyze/report suspicious IP's on AbuseIPDB -
            * usage: AbuseIPDB-Report-Tool.py [args]
            * Arguments: -help     *displays basic usage information.
            *            -log      *use raw access log as input.


    ''')

#<---Start of Program--->

#Trys to catch CLI arguments if they exist
try:
    if sys.argv[1] == '-h' or sys.argv[1] == '-help':
        menu()
        time.sleep(1)
        main()
    else:
        sys.argv[1] =='-l' or sys.argv[1] =='-log'
        accessLog()

#Issue: if user selects 'no' on -l this except will be called and main() will start
except:
    menu()
    time.sleep(1)
    main()
