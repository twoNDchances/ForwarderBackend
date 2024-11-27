from os import getenv
from flask import Flask, request, jsonify
import requests
from elasticsearch import Elasticsearch
import logging


application = Flask(__name__)

ES_HOST = getenv(key='ES_HOST')
ES_USER = getenv(key='ES_USER')
ES_PASS = getenv(key='ES_PASS')
ES_MAX_RESULT = getenv(key='ES_MAX_RESULT')

BACKEND_HOST = getenv(key='BACKEND_HOST')
BACKEND_PORT = getenv(key='BACKEND_PORT')

ANALYZER_HOST = getenv(key='ANALYZER_HOST')
ANALYZER_PORT = getenv(key='ANALYZER_PORT')

CATEGORIES_SQLI_XSS_INDEX_MAPPING = {
    "sqlis": "analyzer-sqlis",
    "xsss": "analyzer-xsss",
}

CATEGORIES_FU_INDEX_MAPPING = {
    "fus": "analyzer-fus"
}

es = Elasticsearch(
    ES_HOST,
    basic_auth=(ES_USER, ES_PASS)
)

def query_enabled_rules(type_attack: dict):
    enabled_rules = []
    for category, index_name in type_attack.items():
        try:
            query = {'match_all': {}}
            response = es.search(index=index_name, query=query, size=ES_MAX_RESULT)
            results = response["hits"]["hits"]
            for result in results:
                rule_name = result['_source']['rule_name']
                enabled_rules.append({
                    "category": category,
                    "rule_name": rule_name,
                    "endpoint": f"/{category}/{rule_name}"
                })
        except Exception as e:
            logging.error(f"Error querying index {index_name}: {e}")
    return enabled_rules


@application.route('/sqlis-xsss', methods=['POST'])
def forward_proxy_sqli_xss():
    try:
        payload = request.json
        if not payload:
            return jsonify({"error": "Invalid payload: no data provided"}), 400
        enabled_rules = query_enabled_rules(type_attack=CATEGORIES_SQLI_XSS_INDEX_MAPPING)
        if not enabled_rules:
            return jsonify({
                "status": "failure",
                "reason": "No enabled rules found"
            }), 404
        responses = []
        for rule in enabled_rules:
            endpoint_url = f"http://{ANALYZER_HOST}:{ANALYZER_PORT}{rule['endpoint']}"
            try:
                response = requests.post(endpoint_url, json=payload)
                responses.append({
                    "endpoint": endpoint_url,
                    "status": response.status_code,
                    "response": response.json()
                })
            except Exception as e:
                logging.error(f"Error forwarding to {endpoint_url}: {e}")
                responses.append({
                    "endpoint": endpoint_url,
                    "error": str(e)
                })

        return jsonify({
            "status": "success",
            "forwarded_responses": responses
        }), 200

    except Exception as e:
        logging.error(f"Error in forward_proxy: {e}")
        return jsonify({"error": str(e)}), 500

@application.route('/fus', methods=['POST'])
def forward_proxy_fu():
    try:
        payload = request.json
        if not payload:
            return jsonify({"error": "Invalid payload: no data provided"}), 400
        enabled_rules = query_enabled_rules(type_attack=CATEGORIES_FU_INDEX_MAPPING)
        if not enabled_rules:
            return jsonify({
                "status": "failure",
                "reason": "No enabled rules found"
            }), 404
        responses = []
        for rule in enabled_rules:
            endpoint_url = f"http://{ANALYZER_HOST}:{ANALYZER_PORT}{rule['endpoint']}"
            try:
                response = requests.post(endpoint_url, json=payload)
                responses.append({
                    "endpoint": endpoint_url,
                    "status": response.status_code,
                    "response": response.json()
                })
            except Exception as e:
                logging.error(f"Error forwarding to {endpoint_url}: {e}")
                responses.append({
                    "endpoint": endpoint_url,
                    "error": str(e)
                })

        return jsonify({
            "status": "success",
            "forwarded_responses": responses
        }), 200

    except Exception as e:
        logging.error(f"Error in forward_proxy: {e}")
        return jsonify({"error": str(e)}), 500

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
        if es.ping() is True:
            break
    logging.basicConfig(level=logging.INFO)
    application.run(host=BACKEND_HOST, port=BACKEND_PORT)
