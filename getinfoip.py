import requests

def send_request_to_device(ip, endpoint, method="GET", data=None, json=None, headers=None):
    url = f"http://{ip}/{endpoint}"
    
    try:
        if method.upper() == "GET":
            response = requests.get(url, headers=headers, timeout=5)
        elif method.upper() == "POST":
            response = requests.post(url, data=data, json=json, headers=headers, timeout=5)
        elif method.upper() == "PUT":
            response = requests.put(url, data=data, json=json, headers=headers, timeout=5)
        
        print(f"Status: {response.status_code}")
        return response
        
    except requests.exceptions.ConnectionError:
        print(f"Failed to connect to {ip}")
    except requests.exceptions.Timeout:
        print(f"Request to {ip} timed out")
    except Exception as e:
        print(f"Error: {e}")


send_request_to_device("192.168.1.100", "status")


send_request_to_device("192.168.1.100", "api/control", 
                      method="POST", 
                      json={"command": "power", "value": "on"})