import requests

# url = "http://192.168.30.21/api/v2/monitor/system/config/backup?destination=file&scope=global"
url = "http://192.168.30.21/api/v2/cmdb/router/static/"
payload = {}
headers = {
    'Authorization': 'Bearer bqqn306h5w01GwG1mkNks0088z6sh5',
    'Accept': 'application/json'
}

response = requests.request("GET", url, headers=headers, data=payload)
response.raise_for_status()

data = response.json()
results = data.get("results", [])

print(response.text)
# for route in results:
#    print(route["seq-num"], route["status"], route["dst"], route["gateway"], route["device"], route["comment"])
