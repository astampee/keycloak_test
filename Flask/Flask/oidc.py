import json
import requests

def create_client_secrets(realm='alchemybox', keycloak='http://localhost:8080/auth/'):
    content = requests.get('{}realms/{}/.well-known/openid-configuration'.format(keycloak, realm)).content
    if not isinstance(content, str):
        content = content.decode('utf-8')
    data = json.loads(content)
        
    with open('client_secrets.json', 'w') as outfile:
        
        #json.loads(content)
        json.dump(data, outfile, sort_keys=True, indent=4)