import redis
import rapidjson as json
import os
import time
import sys
import requests

redis_host = os.getenv('REDIS_HOST', 'localhost')
redis_port = int(os.getenv('REDIS_PORT', 6379))
redis_db = int(os.getenv('REDIS_DB', '2'))
redis_username = os.getenv('REDIS_USERNAME', None)
redis_password = os.getenv('REDIS_PASSWORD', None)

rdata = redis.StrictRedis(host=redis_host, port=redis_port, db=redis_db, password=redis_password, ssl=True)

currency_list = ["ARS", "AUD", "BRL", "BTC", "CAD", "CHF", "CLP", "CNY", "CZK", "DKK", "EUR", "GBP", "HKD", "HUF", "IDR", "ILS", "INR",
                 "JPY", "KRW", "MXN", "MYR", "NOK", "NZD", "PHP", "PKR", "PLN", "RUB", "SEK", "SGD", "THB", "TRY", "TWD", "USD", "ZAR", "SAR", "AED", "KWD", "UAH"]

coingecko_url = 'https://api.coingecko.com/api/v3/coins/nano?localization=false&tickers=false&market_data=true&community_data=false&developer_data=false&sparkline=false'
nano_api_url = 'https://nano.to/known'

def coingecko():
    # rdata.flushall()
    response = requests.get(url=coingecko_url).json()
    if 'market_data' not in response:
        return
    for currency in currency_list:
        # rdata.hset("prices", "coingecko:nano-"+data_name, 0)
        try:
            data_name = currency.lower()
            price_currency = response['market_data']['current_price'][data_name]
            print(rdata.hset("prices", "coingecko:nano-"+data_name, price_currency), "Coingecko NANO-"+currency, price_currency)
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print('exception', exc_type, exc_obj, exc_tb.tb_lineno)
            print("Failed to get price for NANO-"+currency.upper()+" Error")
    # Convert to VES
    # usdprice = float(rdata.hget("prices", "coingecko:nano-usd").decode('utf-8'))
    # bolivarprice = float(rdata.hget("prices", "dolartoday:usd-ves").decode('utf-8'))
    # convertedves = usdprice * bolivarprice
    # rdata.hset("prices", "coingecko:nano-ves", convertedves)
    # print("Coingecko NANO-VES", rdata.hget("prices", "coingecko:nano-ves").decode('utf-8'))
    # Convert to ARS
    # price_ars = float(rdata.hget("prices", "dolarsi:usd-ars").decode('utf-8'))
    # converted_ars = usdprice * price_ars
    # rdata.hset("prices", "coingecko:nano-ars", converted_ars)
    # print("Coingecko NANO-ARS", rdata.hget("prices","coingecko:nano-ars").decode('utf-8'))
    print(rdata.hset("prices", "coingecko:lastupdate",int(time.time())), int(time.time()))


def nano_api():
    response = requests.get(url=nano_api_url).json()
    print(response[0])
    if 'name' not in response[0]:
        print("error getting usernames")
        return
    for user in response:
        print(user)
        rdata.hset("usernames", user["address"], user["name"])

coingecko()
nano_api()

print("Coingecko NANO-USD:", rdata.hget("prices", "coingecko:nano-usd").decode('utf-8'))
print("Coingecko NANO-BTC:", rdata.hget("prices", "coingecko:nano-btc").decode('utf-8'))
print("Last Update:          ", rdata.hget("prices", "coingecko:lastupdate").decode('utf-8'))
