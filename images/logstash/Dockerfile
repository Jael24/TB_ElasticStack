ARG elastic_version
FROM docker.elastic.co/logstash/logstash:${elastic_version}
RUN rm -f /usr/share/logstash/pipeline/logstash.conf
ADD pipeline/ /usr/share/logstash/pipeline/
ADD config/ /usr/share/logstash/config/
