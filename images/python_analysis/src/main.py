import time

import altair as alt
import matplotlib
import numpy as np
import pandas as pd
import schedule
import statsmodels.api as sm
import tad
from elasticsearch import Elasticsearch
from fbprophet import Prophet
from matplotlib import pyplot as plt
from mlxtend.frequent_patterns import apriori
from mlxtend.frequent_patterns import association_rules
from pandas.plotting import register_matplotlib_converters
from statsmodels.tsa.arima_model import ARIMA
from statsmodels.tsa.stattools import adfuller

register_matplotlib_converters()

matplotlib.style.use('ggplot')


class AnalyseLogs:
    """Class that allows to retrieve the logs from elasticsearch, and analyse them"""

    def __init__(self):
        """Initialize the attribute"""
        self.logs = {"CPU Overload", "Nominal CPU utilization"}
        self.transactions = {0: {"CPU Overload": 0}}
        self.id_transaction = 0
        self.cpu_list = []

    def get_last_events(self):
        """Retrieve all the events which occurs in the last 15 seconds, and filter them for detecting CPU overload"""
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
        """Retrieve all the events, and filter them for detecting CPU overload"""
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
                                    "gte": all_cpu_utilization['hits']['hits'][i]['_source']['@timestamp'][
                                           :-1] + "||-20m",
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

    def get_all_cpu_pct(self):
        """Retrieve all the logs which informs about cpu utilization"""
        es = Elasticsearch()
        cpu_utilization = es.search(index="logstash-2020.07.01-000001", body={"query": {
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

        for i in range(cpu_utilization['hits']['total']['value']):
            self.cpu_list.append((cpu_utilization['hits']['hits'][i]['_source']['@timestamp'][:-5],
                                  cpu_utilization['hits']['hits'][i]['_source']['system']['cpu']['total']['pct']))

    def market_basket_analysis(self):
        """Compute a market basket analysis on the logs stored in the class.
           Inspired by https://pbpython.com/market-basket-analysis.html"""
        list_articles = list(self.logs)

        list_occ = []

        for k, v in self.transactions.items():
            list_occ.append([])

            for article in list_articles:
                list_occ[k].append(v[article] if (article in v) else 0)

        df = pd.DataFrame(list_occ, columns=list_articles)

        frequent_itemsets = apriori(df, min_support=0.05, use_colnames=True)

        # Create the rules
        rules = association_rules(frequent_itemsets, metric="lift", min_threshold=1)

        # print(rules[rules['consequents'] == {'CPU Overload'}]['consequents'])

    # def get_stationarity(self, timeseries):
    # """Get the stationarity of a timeseries. Copied from https://moncoachdata.com/blog/modele-arima-avec-python/"""
    #
    #     # Statistiques mobiles
    #     rolling_mean = timeseries.rolling(window=12).mean()
    #     rolling_std = timeseries.rolling(window=12).std()
    #
    #     # tracé statistiques mobiles
    #     original = plt.plot(timeseries, color='blue', label='Origine')
    #     mean = plt.plot(rolling_mean, color='red', label='Moyenne Mobile')
    #     std = plt.plot(rolling_std, color='black', label='Ecart-type Mobile')
    #     plt.legend(loc='best')
    #     plt.title('Moyenne et écart-type Mobiles')
    #     plt.show(block=False)
    #
    #     # Test Dickey–Fuller :
    #     result = adfuller(timeseries['Passengers'])
    #     print('Statistiques ADF : {}'.format(result[0]))
    #     print('p-value : {}'.format(result[1]))
    #     print('Valeurs Critiques :')
    #     for key, value in result[4].items():
    #         print('\t{}: {}'.format(key, value))

    def arima_forecast(self, csv_file, start_plot, end_plot, arima_parameters):
        """Compute a forecasting operation with an ARIMA algorithm on a timeseries read in a CSV file
        Inspired from https://moncoachdata.com/blog/modele-arima-avec-python/"""
        df = pd.read_csv(csv_file, parse_dates=['Date'], index_col=['Date'])

        model = ARIMA(df, order=arima_parameters)
        results = model.fit(disp=-1)
        fig = results.plot_predict(start_plot, end_plot)

    def dparserfunc(self, date):
        """Parse a date and create a datetime from a string"""
        return pd.datetime.strptime(date, '%Y-%m-%d %H:%M:%S')

    # def twitter_anomaly_detection(self):
    # """Test using the tad library from https://github.com/Marcnuth/AnomalyDetection but doesn't work"""
    #     # first run the models
    #     twitter_example_data = pd.read_csv('test_data_cpu.csv', index_col='timestamp',
    #                                        parse_dates=True, squeeze=True,
    #                                        date_parser=self.dparserfunc)
    #     results = tad.anomaly_detect_ts(twitter_example_data, max_anoms=0.05, alpha=0.05, direction='both')
    #
    #     # # format the twitter data nicely
    #     # twitter_example_data['timestamp'] = pd.to_datetime(twitter_example_data['timestamp'])
    #     # twitter_example_data.set_index('timestamp', drop=True)
    #     values = results['anoms'].get_values()
    #
    #     print(values)
    #     # make a nice plot
    #     f, ax = plt.subplots(2, 1, sharex=True)
    #     # ax[0].plot(twitter_example_data['timestamp'], twitter_example_data['count'], 'b')
    #     ax[0].plot(results['anoms'].index, results['anoms']['anoms'], 'ro')
    #     ax[0].set_title('Detected Anomalies')
    #     ax[1].set_xlabel('Time Stamp')
    #     ax[0].set_ylabel('Count')
    #     ax[1].plot(results['anoms'].index, results['anoms']['anoms'], 'b')
    #     ax[1].set_ylabel('Anomaly Magnitude')
    #     plt.show()

    def plot_anomaly(self, df, timeseries):
        """ Plot a graph from a timeseries with anomaly. The timeseries should be create by Prophet
        Copied from https://towardsdatascience.com/anomaly-detection-time-series-4c661f6f165f"""
        actual_vals = timeseries.actuals.values
        actual_log = np.log10(actual_vals)

        train, test = actual_vals[0:-70], actual_vals[-70:]

        train_log, test_log = np.log10(train), np.log10(test)

        my_order = (1, 1, 1)
        my_seasonal_order = (0, 1, 1, 7)

        history = [x for x in train_log]
        predictions = list()
        predict_log = list()
        for t in range(len(test_log)):
            model = sm.tsa.SARIMAX(history, order=my_order, seasonal_order=my_seasonal_order,
                                   enforce_stationarity=False, enforce_invertibility=False)
            model_fit = model.fit(disp=0)
            output = model_fit.forecast()
            predict_log.append(output[0])
            yhat = 10 ** output[0]
            predictions.append(yhat)
            obs = test_log[t]
            history.append(obs)

    def fit_predict_model(self, dataframe, interval_width=0.85, changepoint_range=0.95):
        """Create the model used by prophet to detect anomalies
           Inspired by https://towardsdatascience.com/anomaly-detection-time-series-4c661f6f165f"""
        m = Prophet(daily_seasonality=False, yearly_seasonality=False, weekly_seasonality=False,
                    interval_width=interval_width,
                    changepoint_range=changepoint_range)
        m = m.fit(dataframe)
        forecast = m.predict(dataframe)
        forecast['fact'] = dataframe['y'].reset_index(drop=True)
        return forecast

    def detect_anomalies(self, forecast):
        """Detect anomalies in the forecast realized by Prophet
           Copied from https://towardsdatascience.com/anomaly-detection-time-series-4c661f6f165f"""
        forecasted = forecast[['ds', 'trend', 'yhat', 'yhat_lower', 'yhat_upper', 'fact']].copy()

        forecasted['anomaly'] = 0
        forecasted.loc[forecasted['fact'] > forecasted['yhat_upper'], 'anomaly'] = 1
        forecasted.loc[forecasted['fact'] < forecasted['yhat_lower'], 'anomaly'] = -1

        # anomaly importances
        forecasted['importance'] = 0
        forecasted.loc[forecasted['anomaly'] == 1, 'importance'] = \
            (forecasted['fact'] - forecasted['yhat_upper']) / forecast['fact']
        forecasted.loc[forecasted['anomaly'] == -1, 'importance'] = \
            (forecasted['yhat_lower'] - forecasted['fact']) / forecast['fact']

        return forecasted

    def plot_anomalies(self, forecasted):
        """Show plot with anomalies
           Inspired from https://towardsdatascience.com/anomaly-detection-time-series-4c661f6f165f"""
        interval = alt.Chart(forecasted).mark_area(interpolate="basis", color='#adadad').encode(
            x=alt.X('ds:T', title='Time'),
            y='yhat_upper',
            y2='yhat_lower',
            tooltip=['ds', 'fact', 'yhat_lower', 'yhat_upper']
        ).interactive().properties(
            title='Anomaly Detection'
        )

        fact = alt.Chart(forecasted[forecasted.anomaly == 0]).mark_circle(size=15, opacity=0.7, color='Black').encode(
            x='ds:T',
            y=alt.Y('fact', title='CPU Utilization [%]'),
            tooltip=['ds', 'fact', 'yhat_lower', 'yhat_upper']
        ).interactive()

        anomalies = alt.Chart(forecasted[forecasted.anomaly != 0]).mark_circle(size=30, color='Red').encode(
            x='ds:T',
            y=alt.Y('fact', title='CPU Utilization [%]'),
            tooltip=['ds', 'fact', 'yhat_lower', 'yhat_upper'],
            size=alt.Size('importance', legend=None)
        ).interactive()

        return alt.layer(interval, fact, anomalies) \
            .properties(width=870, height=450) \
            .configure_title(fontSize=20)


alt.renderers.enable('altair_viewer')

if __name__ == '__main__':
    a = AnalyseLogs()

    # Dataframe used by the Prophet library
    df = pd.read_csv('test_data_cpu.csv', parse_dates=['ds'])
    df_sorted = df.sort_values(by=['ds'])
    df_sorted['y'] = df['y'].apply(lambda x: x * 100 / 4)

    # Analyze the time series with Prophet model, and show the results
    forecast = a.fit_predict_model(df_sorted)
    forecasted = a.detect_anomalies(forecast)
    fig1 = a.plot_anomalies(forecasted)
    fig1.show()

    # # Read the logs with CPU utilization information and forecast the values
    # a.arima_forecast('airline_passengers.csv', 1, 241, (2,1,1))

    # Useful for the real-time analysis
    # schedule.every(10).seconds.do(a.get_last_events)
    # schedule.every(10).seconds.do(a.print_state)
    # schedule.every(2).minutes.do(a.market_basket_analysis)
    #
    # while 1:
    #     schedule.run_pending()
    #     time.sleep(1)
