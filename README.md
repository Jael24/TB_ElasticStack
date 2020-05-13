Repository for a complete working Elastic Stack pipeline (Logstash - Elasticsearch - Kibana). Running with Docker.

## Running the Elastic Stack

- Make sure you have `docker` and `docker-compose` installed.
- Move to the docker topology folder.
    - `cd topology`
- Run with docker-compose
    - `docker-compose up --build -d`
- You can now send logs with a Filebeat agent to `<IP>:5044`.
