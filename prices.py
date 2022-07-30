import asyncio
import redis
import rapidjson as json
import os
import time
import sys
import requests
from rpc import RPC, allowed_rpc_actions

rpc_url = os.getenv('RPC_URL', 'http://[::1]:7076')
work_url = os.getenv('WORK_URL', None)
rpc = RPC(rpc_url, False, work_url=work_url, price_prefix='coingecko:nano')

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
nano_api_balances_url = 'https://nano.to/'

funding_addresses = ["nano_38713x95zyjsqzx6nm1dsom1jmm668owkeb9913ax6nfgj15az3nu8xkx579", "nano_3xnr31q9p8pce5j4qjwnhmfwkry1mgs67x63149zp6kdbcztfmfqjxwb9bw7", "nano_1u844awm5ch3ktwwzpzjfchj54ay5o6a7kyop5jycue7bw5jr117m15tx8oa", "nano_1f5z6gy3mf6gyyen79sidopxizcp59u6iahcmhtatti3qeh7q7m9w5s548nc", "nano_14qojirkhwgekfpf1jbqfd58ks7t6rrjtzuaetytkxmmuhdgx5cmjhgr5wu5", "nano_3mt48meumbxzw3nsnpq43nzrrnx8rb6sjrxtwqdix564htc73hhra4gbuipo", "nano_3uzdra7hdf9qb19a3g61jrsyt8zkthexrtyx186oc8auyegpir8ezm6y9sra",
"nano_3wneupytd8wxgjrydiq4axoipr9wbpkdycd83bfibemjgmreere1tgnn7ajh", "nano_13ddtgi44o3on9j1d6ughjakoe3s9m515q8fasissky7snsomf93cywsiq68", "nano_1n8syxftoknbadk8k46ou7rstawfmfr8qh1jq1dkuuskrspb9yygkise9drr", "nano_16uomspu1foykg7mumh39i3iosi73fsy74xfsr6rupiw3wzcrea8tnpax67h", "nano_1rw4ybt4hagog4uyhqd7mnaogeu6e4ik4kdswfbh9g3zfiyp1hz968mufyni", "nano_3s9dyxh6qm5uody1ou9g6a6g7qseqer1mgrwwoctwdgs37qt3i57w1dwt7wh"]

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
    if 'name' not in response[0]:
        print("error getting usernames")
        return
    for user in response:
        rdata.hset("usernames", user["address"], user["name"])

def funding_balances():
    loop = asyncio.get_event_loop()
    for address in funding_addresses:
        response = loop.run_until_complete(rpc.json_post({'action': 'account_balance', 'account': address}))
        if response is not None:
            balance = int(response['balance']) + int(response['receivable'])
            rdata.hset("funding_balances", address, balance)



coingecko()
nano_api()
funding_balances()

# print("Coingecko NANO-USD:", rdata.hget("prices", "coingecko:nano-usd").decode('utf-8'))
# print("Coingecko NANO-BTC:", rdata.hget("prices", "coingecko:nano-btc").decode('utf-8'))
# print("Last Update: ", rdata.hget("prices", "coingecko:lastupdate").decode('utf-8'))
