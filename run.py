from flask import Flask, request
from elasticsearch import Elasticsearch
from json import loads
from os import getenv
import requests


application = Flask(__name__)

ES_HOST = getenv(key='ES_HOST')
ES_USER = getenv(key='ES_USER')
ES_PASS = getenv(key='ES_PASS')
ES_MAX_RESULT = getenv(key='ES_MAX_RESULT')

BACKEND_HOST = getenv(key='BACKEND_HOST')
BACKEND_PORT = getenv(key='BACKEND_PORT')

ANALYZER_HOST = getenv(key='ANALYZER_HOST')
ANALYZER_PORT = getenv(key='ANALYZER_PORT')

CATEGORIES_INDEX_MAPPING = {
    'sqlis': 'analyzer-sqlis',
    'xsss': 'analyzer-xsss',
    'fus': 'analyzer-fus'
}

response_elasticsearch = Elasticsearch(
    ES_HOST,
    basic_auth=(ES_USER, ES_PASS)
)

def query_enabled_rules():
    enabled_rules = []
    for category, index_name in CATEGORIES_INDEX_MAPPING.items():
        response = response_elasticsearch.search(index=index_name, query={'match_all': {}}, size=ES_MAX_RESULT)
        results = response['hits']['hits']
        for result in results:
            rule_name = result['_source']['rule_name']
            enabled_rules.append(f'/{category}/{rule_name}')
    return enabled_rules


@application.route(rule='/', methods=['POST'])
def forward_proxy():
    if response_elasticsearch.ping() is False:
        return {
            'type': 'forwarders',
            'data': None,
            'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
        }, 500
    try:
        payload = loads(request.data)
    except:
        return {
            'type': 'forwarders',
            'data': None,
            'reason': 'BadRequest: Body must be JSON'
        }, 400
    enabled_rules = query_enabled_rules()
    for rule in enabled_rules:
        endpoint_url = f'http://{ANALYZER_HOST}:{ANALYZER_PORT}{rule}'
        try:
            response = requests.post(endpoint_url, json=payload, headers={'Content-Type': 'application/json'})
            if response.status_code != 200:
                print(f'[Warning] Send payload unsuccessfully with status {response.status_code} to "{rule}"')
                continue
        except Exception as error:
            print(f'[Error] Send payload unsuccessfully with error {str(error)} to "{rule}"')
            continue
    return {
        'type': 'forwarders',
        'data': None,
        'reason': 'Success'
    }

if __name__ == '__main__':
    environment_variables = {
        'ES_HOST': 'http://elasticsearch:9200',
        'ES_USER': 'elastic',
        'ES_PASS': 'elastic',
        'ES_MAX_RESULT': 1000000000,
        'BACKEND_HOST': '0.0.0.0',
        'BACKEND_PORT': 9946,
        'ANALYZER_HOST': 'analyzer',
        'ANALYZER_PORT': 9947
    }
    config = {variable: getenv(variable, default) for variable, default in environment_variables.items()}
    print('========== Environment Variable Configurations ==========')
    for variable, value in config.items():
        if variable in ['ES_PASS']:
            print(f'{variable} = {"*" * value.__len__()}')
        else:
            print(f'{variable} = {value}')
    print('=========================================================', end='\n\n')
    while True:
        if response_elasticsearch.ping() is False:
            continue
        if (
            response_elasticsearch.indices.exists(index='analyzer-sqlis') and 
            response_elasticsearch.indices.exists(index='analyzer-xsss') and 
            response_elasticsearch.indices.exists(index='analyzer-fus')
        ):
            break
    application.run(host=BACKEND_HOST, port=BACKEND_PORT)
