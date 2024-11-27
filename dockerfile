FROM python:3

WORKDIR /forwarders

COPY requirements.txt ./
RUN apt update -y && pip install --no-cache-dir -r requirements.txt

COPY . .

ENV ES_HOST="http://elasticsearch:9200" \
    ES_USER="elastic" \
    ES_PASS="elastic" \
    ES_MAX_RESULT=1000000000 \
    BACKEND_HOST="0.0.0.0" \
    BACKEND_PORT=9946 \
    ANALYZER_HOST="analyzer" \
    ANALYZER_PORT=9947

CMD [ "python", "./run.py" ]
