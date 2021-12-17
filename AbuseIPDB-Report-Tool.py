import sys
import requests
import json
import pandas as pd

#Globals
apiKey = open("R:\Path\To\AbuseIPDBapiKey.txt", "r")
headers = {
    'Accept': 'application/json',
    'Key': apiKey.read()
}
df = pd.read_csv("\Categories.csv")
df_reset=df.set_index('#')

#Report the suspicious IP. takes ip and comment variables returned from suspectIP()
def reportIP(ip, comment, attackCategories):
    url = 'https://api.abuseipdb.com/api/v2/report'
    # String holding parameters to pass in json format
    params = {
        'ip': ip,
        'categories': attackCategories,   #fix with db
        'comment': comment
        }
    response = requests.request(method='POST', url=url, headers=headers, params=params)
    # Formatted output
    decodedResponse = json.loads(response.text)
    jsondataReport = json.dumps(decodedResponse, sort_keys=True, indent=4)
    print(jsondataReport)

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

#main function
def main():
    # Get user input for analysis
    ip = input('Enter IP:')
    request = input('Enter Request:')
    time = input('Enter Time:')
    size = input('Enter Size:')
    client = input('Enter Client:')
    ref = input('Enter Refering URL:')
    #Prints out the .csv file of Attack Categories
    print(df_reset)
    attackCategories = input('Enter Attack Categories That Apply (1,2,3..etc):')
    comment = 'IP:[' + ip + '] ' + 'Request:[' + request + '] ' + 'Time:[' + time + '] ' + 'Size:[' + size + '] ' + 'Client:[ ' + client + '] ' + 'Referring URL:[' + ref + '] '
    checkIP(ip)
    reportIPAddr = input('Report this IP? yes/no/exit:')
    if reportIPAddr == 'yes' or 'Yes' or 'y' or 'Y':
        reportIP(ip, comment, attackCategories)
    elif reportIPAddr == 'exit':
        sys.exit()
    else:
        input('press control+c to leave')

main()
