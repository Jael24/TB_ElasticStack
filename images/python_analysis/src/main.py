import time

from elasticsearch import Elasticsearch
import schedule
import pandas as pd
from mlxtend.frequent_patterns import apriori
from mlxtend.frequent_patterns import association_rules


class AnalyseLogs:
    def __init__(self):
        self.logs = {"CPU Overload", "Nominal CPU utilization"}
        self.transactions = {0: {"CPU Overload": 0}}
        self.id_transaction = 0

    def get_last_events(self):
        es = Elasticsearch()
        last_cpu_utilization = es.search(index="logstash-2020.07.01-000001", body={"query": {
            "bool": {
                "must": [
                    {
                        "match": {
                            "agent.type": "metricbeat"
                        }
                    },
                    {
                        "match": {
                            "service.type": "system"
                        }
                    },
                    {
                        "match": {
                            "event.dataset": "system.cpu"
                        }
                    },
                    {
                        "range": {
                            "@timestamp": {
                                "gte": "now-15s",
                                "lt": "now"
                            }
                        }
                    }
                ]
            }
        }
        })

        last_logs = es.search(index="logstash-2020.07.01-000001", body={"query": {
            "bool": {
                "must": [
                    {
                        "match": {
                            "agent.type": "filebeat"
                        }
                    },
                    {
                        "range": {
                            "@timestamp": {
                                "gte": "now-15s",
                                "lt": "now"
                            }
                        }
                    }
                ]
            }
        }
        })

        # Read the logs of the 15 last seconds, and, if there are new logs, store them.
        # Create also a list with the log_message of all these logs
        last_messages = []

        for i in range(last_logs['hits']['total']['value']):
            self.logs.add(last_logs['hits']['hits'][i]['_source']['log_message'])
            last_messages.append(last_logs['hits']['hits'][i]['_source']['log_message'])

        # Store the information about logs in a dictionary, in transaction form.
        # We store here the information about id - 1, because the effect on the CPU is not immediate.

        if self.id_transaction != 0:
            for lm in last_messages:
                self.transactions[self.id_transaction - 1][lm] = 0
            for k, v in self.transactions[self.id_transaction - 1].items():
                if k in last_messages:
                    self.transactions[self.id_transaction - 1][k] = 1

        # Indicate if there is a CPU overload or not.
        self.transactions[self.id_transaction] = dict.fromkeys(self.logs, 0)
        if last_cpu_utilization['hits']['hits'][0]['_source']['system']['cpu']['total']['pct'] > 2.0:
            self.transactions[self.id_transaction]["CPU Overload"] = 1
        else:
            self.transactions[self.id_transaction]["Nominal CPU utilization"] = 1

        self.id_transaction += 1

    def get_all_events(self):
        es = Elasticsearch()
        all_cpu_utilization = es.search(index="logstash-2020.07.01-000001", body={"query": {
            "bool": {
                "must": [
                    {
                        "match": {
                            "agent.type": "metricbeat"
                        }
                    },
                    {
                        "match": {
                            "service.type": "system"
                        }
                    },
                    {
                        "match": {
                            "event.dataset": "system.cpu"
                        }
                    }
                ]
            }
        }
        }, size=10000)

        all_applicative_logs = es.search(index="logstash-2020.07.01-000001", body={"query": {
            "bool": {
                "must": [
                    {
                        "match": {
                            "agent.type": "filebeat"
                        }
                    }
                ]
            }
        }
        }, size=10000)

        # Read all log_message
        for i in range(all_applicative_logs['hits']['total']['value']):
            if "_grokparsefailure" not in all_applicative_logs['hits']['hits'][i]['_source']['tags']:
                self.logs.add(all_applicative_logs['hits']['hits'][i]['_source']['log_message'])

        # For each CPU Utilization data, store the applicative logs who arrived in the last 20 minutes
        for i in range(all_cpu_utilization['hits']['total']['value']):
            last_applicative_logs = es.search(index="logstash-2020.07.01-000001", body={"query": {
                "bool": {
                    "must": [
                        {
                            "match": {
                                "agent.type": "filebeat"
                            }
                        },
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": all_cpu_utilization['hits']['hits'][i]['_source']['@timestamp'][:-1] + "||-20m",
                                    "lt": all_cpu_utilization['hits']['hits'][i]['_source']['@timestamp'][:-1]
                                }
                            }
                        }
                    ]
                }
            }
            })

            self.transactions[i] = dict.fromkeys(self.logs, 0)

            if all_cpu_utilization['hits']['hits'][i]['_source']['system']['cpu']['total']['pct'] > 2.0:
                self.transactions[i]["CPU Overload"] = 1
            else:
                self.transactions[i]["Nominal CPU utilization"] = 1

            for j in self.logs:
                log_is_present = False
                for k in last_applicative_logs['hits']['hits']:
                    if "_grokparsefailure" not in k['_source']['tags'] and k['_source']['log_message'] == j:
                        log_is_present = True
                        break

                self.transactions[i][j] = 1 if log_is_present else 0

    def market_basket_analysis(self):
        list_articles = list(self.logs)

        list_occ = []

        for k, v in self.transactions.items():
            list_occ.append([])

            for article in list_articles:
                list_occ[k].append(v[article] if (article in v) else 0)

        df = pd.DataFrame(list_occ, columns=list_articles)

        # Show DataFrame
        # with pd.option_context('display.max_rows', None, 'display.max_columns',
        #                        None):  # more options can be specified also
        #     print("dataframe : ", df)

        frequent_itemsets = apriori(df, min_support=0.05, use_colnames=True)

        # Create the rules
        rules = association_rules(frequent_itemsets, metric="lift", min_threshold=1)

        print(rules[rules['consequents'] == {'CPU Overload'}]['consequents'])


    def print_state(self):
        print("logs (articles) : ", self.logs)

        print("transactions : ", self.transactions)

        print("id transaction : ", self.id_transaction)

        print("-------------------------------------------------------------")


if __name__ == '__main__':
    a = AnalyseLogs()

    a.get_all_events()
    a.market_basket_analysis()

    # schedule.every(10).seconds.do(a.get_last_events)
    # schedule.every(10).seconds.do(a.print_state)
    # schedule.every(2).minutes.do(a.market_basket_analysis)
    #
    # while 1:
    #     schedule.run_pending()
    #     time.sleep(1)
