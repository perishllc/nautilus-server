#!/usr/bin/env python
from dotenv import load_dotenv
load_dotenv()

import argparse
import asyncio
import ipaddress
import rapidjson as json
import logging
import os
import sys
import time
import uuid
import uvloop
import socketio
from logging.handlers import TimedRotatingFileHandler, WatchedFileHandler

import aiofcm
import aioredis
from aiohttp import ClientSession, WSMessage, WSMsgType, log, web
import aiohttp_cors

from rpc import RPC, allowed_rpc_actions
from util import Util
from nano_websocket import WebsocketClient
from alerts import get_active_alert, get_active_funding

# verify block signature:
from ed25519_blake2b import BadSignatureError, SigningKey, VerifyingKey
from binascii import hexlify, unhexlify

# split gifts:
import requests
import random
from nanolib import Block, generate_account_id, generate_account_private_key, get_account_id, generate_seed, get_account_public_key
import nanopy

asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

# Configuration arguments

parser = argparse.ArgumentParser(description="Nautilus Wallet Server")
parser.add_argument('-b', '--banano', action='store_true', help='Run for BANANO (Kalium-mode)', default=False)
parser.add_argument('--host', type=str, help='Host to listen on (e.g. 127.0.0.1)', default='127.0.0.1')
parser.add_argument('--path', type=str, help='(Optional) Path to run application on (for unix socket, e.g. /tmp/nautilusapp.sock', default=None)
parser.add_argument('-p', '--port', type=int, help='Port to listen on', default=5076)
# parser.add_argument('-ws', '--websocket-url', type=str, help='Nano websocket URI', default='ws://[::1]:7078')
parser.add_argument('--log-file', type=str, help='Log file location', default='nautiluscast.log')
parser.add_argument('--log-to-stdout', action='store_true', help='Log to stdout', default=False)

options = parser.parse_args()

try:
    listen_host = str(ipaddress.ip_address(options.host))
    listen_port = int(options.port)
    redis_host = os.getenv('REDIS_HOST', 'localhost')
    redis_port = int(os.getenv('REDIS_PORT', 6379))
    redis_db = int(os.getenv('REDIS_DB', '2'))
    redis_username = os.getenv('REDIS_USERNAME', None)
    redis_password = os.getenv('REDIS_PASSWORD', None)
    branch_api_key = os.getenv('BRANCH_API_KEY', None)
    log_file = options.log_file
    app_path = options.path
    if app_path is None:
        server_desc = f'on {listen_host} port {listen_port}'
    else:
        server_desc = f'on {app_path}'
    if options.banano:
        banano_mode = True
        print(f'Starting KALIUM Server (BANANO) {server_desc}')
    else:
        banano_mode = False
        print(f'Starting NAUTILUS Server (NANO) {server_desc}')
except Exception as e:
    parser.print_help()
    sys.exit(0)

price_prefix = 'coingecko:nano' if not banano_mode else 'coingecko:banano'

# Environment configuration
ws_url = os.getenv('WS_URL', 'ws://[::1]:7078')
rpc_url = os.getenv('RPC_URL', 'http://[::1]:7076')
work_url = os.getenv('WORK_URL', None)
fcm_api_key = os.getenv('FCM_API_KEY', None)
fcm_sender_id = os.getenv('FCM_SENDER_ID', None)
debug_mode = True if int(os.getenv('DEBUG', 1)) != 0 else False
nonce_timeout_seconds = int(os.getenv('NONCE_TIMEOUT', 100))
nonce_separator = '^'

# Objects

loop = asyncio.get_event_loop()
rpc = RPC(rpc_url, banano_mode, work_url=work_url, price_prefix=price_prefix)
util = Util(banano_mode)

# a complete hack for mocking structs to pass to functions:
class Object(object):
    pass

# all currency conversions that are available
currency_list = ["BTC", "ARS", "AUD", "BRL", "CAD", "CHF", "CLP", "CNY", "CZK", "DKK", "EUR", "GBP", "HKD", "HUF", "IDR",
                 "ILS", "INR", "JPY", "KRW", "MXN", "MYR", "NOK", "NZD", "PHP", "PKR", "PLN", "RUB", "SEK", "SGD",
                 "THB", "TRY", "TWD", "USD", "VES", "ZAR", "SAR", "AED", "KWD", "UAH"]

# Push notifications

async def delete_fcm_token_for_account(account : str, token : str, r : web.Request):
    await r.app['rdata'].delete(token)

async def update_fcm_token_for_account(account : str, token : str, r : web.Request, v2 : bool = False):
    """Store device FCM registration tokens in redis"""
    redisInst = r.app['rdata']
    await set_or_upgrade_token_account_list(account, token, r, v2=v2)
    # Keep a list of tokens associated with this account
    cur_list = await redisInst.get(account)
    if cur_list is not None:
        cur_list = json.loads(cur_list.replace('\'', '"'))
    else:
        cur_list = {}
    if 'data' not in cur_list:
        cur_list['data'] = []
    if token not in cur_list['data']:
        cur_list['data'].append(token)
    await redisInst.set(account, json.dumps(cur_list))

async def get_or_upgrade_token_account_list(account : str, token : str, r : web.Request, v2 : bool = False) -> list:
    redisInst = r.app['rdata']
    curTokenList = await redisInst.get(token)
    if curTokenList is None:
        return []
    else:
        try:
            curToken = json.loads(curTokenList)
            return curToken
        except Exception:
            curToken = curTokenList
            await redisInst.set(token, json.dumps([curToken]), expire=2592000)
            if account != curToken:
                return []
    return json.loads(await redisInst.get(token))

async def set_or_upgrade_token_account_list(account : str, token : str, r : web.Request, v2 : bool = False) -> list:
    redisInst = r.app['rdata']
    curTokenList = await redisInst.get(token)
    if curTokenList is None:
        await redisInst.set(token, json.dumps([account]), expire=2592000) 
    else:
        try:
            curToken = json.loads(curTokenList)
            if account not in curToken:
                curToken.append(account)
                await redisInst.set(token, json.dumps(curToken), expire=2592000)
        except Exception as e:
            curToken = curTokenList
            await redisInst.set(token, json.dumps([curToken]), expire=2592000)
    return json.loads(await redisInst.get(token))

async def get_fcm_tokens(account : str, r : web.Request, v2 : bool = False) -> list:
    """Return list of FCM tokens that belong to this account"""
    redisInst = r.app['rdata']
    tokens = await redisInst.get(account)
    if tokens is None:
        return []
    tokens = json.loads(tokens.replace('\'', '"'))
    # Rebuild the list for this account removing tokens that dont belong anymore
    new_token_list = {}
    new_token_list['data'] = []
    if 'data' not in tokens:
        return []
    for t in tokens['data']:
        account_list = await get_or_upgrade_token_account_list(account, t, r, v2=v2)
        if account not in account_list:
            continue
        new_token_list['data'].append(t)
    await redisInst.set(account, json.dumps(new_token_list))
    return new_token_list['data']

### END Utility functions

# Primary handler for all websocket connections
async def handle_user_message(r : web.Request, message : str, ws : web.WebSocketResponse = None):
    """Process data sent by client"""
    print(message)
    address = util.get_request_ip(r)
    uid = ws.id if ws is not None else '0'
    now = int(round(time.time() * 1000))
    if address in r.app['last_msg']:
        if (now - r.app['last_msg'][address]['last']) < 25:
            if r.app['last_msg'][address]['count'] > 3:
                log.server_logger.error('client messaging too quickly: %s ms; %s; %s; User-Agent: %s', str(
                    now - r.app['last_msg'][address]['last']), address, uid, str(
                    r.headers.get('User-Agent')))
                return None
            else:
                r.app['last_msg'][address]['count'] += 1
        else:
            r.app['last_msg'][address]['count'] = 0
    else:
        r.app['last_msg'][address] = {}
        r.app['last_msg'][address]['count'] = 0
    r.app['last_msg'][address]['last'] = now
    log.server_logger.info('request; %s, %s, %s', message, address, uid)
    if message not in r.app['active_messages']:
        r.app['active_messages'].add(message)
    else:
        log.server_logger.error('request already active; %s; %s; %s', message, address, uid)
        return None
    ret = None
    try:
        request_json = json.loads(message)
        if request_json['action'] in allowed_rpc_actions:
            if 'request_id' in request_json:
                requestid = request_json['request_id']
            else:
                requestid = None

            # adjust counts so nobody can block the node with a huge request
            if 'count' in request_json:
                if (int(request_json['count']) < 0) or (int(request_json['count']) > 3500):
                    request_json['count'] = 3500

            # rpc: account_subscribe (only applies to websocket connections)
            if request_json['action'] == "account_subscribe" and ws is not None:
                # If account doesnt match the uuid self-heal
                resubscribe = True
                if 'uuid' in request_json and request_json['uuid'] is not None:
                    # Perform multi-account upgrade if not already done
                    account = await r.app['rdata'].hget(request_json['uuid'], "account")
                    # No account for this uuid, first subscribe
                    if account is None:
                        resubscribe = False
                    else:
                        # If account isn't stored in list-format, modify it so it is
                        # If it already is, add this account to the list
                        try:
                            account_list = json.loads(account)
                            if 'account' in request_json and request_json['account'].lower() not in account_list:
                                account_list.append(request_json['account'].lower())
                                await r.app['rdata'].hset(request_json['uuid'], "account", json.dumps(account_list))
                        except Exception:
                            if 'account' in request_json and request_json['account'].lower() != account.lower():
                                resubscribe = False
                            else:
                                # Perform upgrade to list style
                                account_list = []
                                account_list.append(account.lower())
                                await r.app['rdata'].hset(request_json['uuid'], "account", json.dumps(account_list))
                # already subscribed, reconnect (websocket connections)
                if 'uuid' in request_json and request_json['uuid'] is not None and resubscribe:
                    if uid in r.app['clients']:
                        del r.app['clients'][uid]
                    uid = request_json['uuid']
                    ws.id = uid
                    r.app['clients'][uid] = ws
                    log.server_logger.info('reconnection request;' + address + ';' + uid)
                    try:
                        if 'currency' in request_json and request_json['currency'] in currency_list:
                            currency = request_json['currency']
                            r.app['cur_prefs'][uid] = currency
                            await r.app['rdata'].hset(uid, "currency", currency)
                        else:
                            setting = await r.app['rdata'].hget(uid, "currency")
                            if setting is not None:
                                r.app['cur_prefs'][uid] = setting
                            else:
                                r.app['cur_prefs'][uid] = 'usd'
                                await r.app['rdata'].hset(uid, "currency", 'usd')

                        # Get relevant account
                        account_list = json.loads(await r.app['rdata'].hget(uid, "account"))
                        if 'account' in request_json:
                            account = request_json['account']
                        else:
                            # Legacy connections
                            account = account_list[0]
                        if account.replace("nano_", "xrb_") in account_list:
                            account_list.remove(account.replace("nano_", "xrb_"))
                            account = account.replace('xrb_', 'nano_')
                            account_list.append(account)
                            await r.app['rdata'].hset(uid, "account", json.dumps(account_list))
                        await rpc.rpc_reconnect(ws, r, account)
                        # Store FCM token for this account, for push notifications
                        if 'fcm_token_v2' in request_json and 'notification_enabled' in request_json:
                            if request_json['notification_enabled']:
                                await update_fcm_token_for_account(account, request_json['fcm_token_v2'], r, v2=True)
                            else:
                                await delete_fcm_token_for_account(account, request_json['fcm_token_v2'], r)
                    except Exception as e:
                        log.server_logger.error('reconnect error; %s; %s; %s', str(e), address, uid)
                        reply = {'error': 'reconnect error', 'details': str(e)}
                        if requestid is not None: reply['request_id'] = requestid
                        ret = json.dumps(reply)
                # new user, setup uuid(or use existing if available) and account info
                else:
                    log.server_logger.info('subscribe request; %s; %s', util.get_request_ip(r), uid)
                    try:
                        if 'currency' in request_json and request_json['currency'] in currency_list:
                            currency = request_json['currency']
                        else:
                            currency = 'usd'
                        await rpc.rpc_subscribe(ws, r, request_json['account'].replace("nano_", "xrb_"), currency)
                        # Store FCM token if available, for push notifications
                        if 'fcm_token_v2' in request_json and 'notification_enabled' in request_json:
                            if request_json['notification_enabled']:
                                await update_fcm_token_for_account(request_json['account'], request_json['fcm_token_v2'], r, v2=True)
                            else:
                                await delete_fcm_token_for_account(request_json['account'], request_json['fcm_token_v2'], r)
                    except Exception as e:
                        log.server_logger.error('subscribe error;%s;%s;%s', str(e), address, uid)
                        reply = {'error': 'subscribe error', 'details': str(e)}
                        if requestid is not None: reply['request_id'] = requestid
                        ret = json.dumps(reply)
    
            elif request_json['action'] == "fcm_update":
                # Updating FCM token
                if 'fcm_token_v2' in request_json and 'account' in request_json and 'enabled' in request_json:
                    if request_json['enabled']:
                        await update_fcm_token_for_account(request_json['account'], request_json['fcm_token_v2'], r, v2=True)
                    else:
                        await delete_fcm_token_for_account(request_json['account'], request_json['fcm_token_v2'], r)
            # rpc: price_data
            elif request_json['action'] == "price_data":
                log.server_logger.info('price data request;%s;%s', util.get_request_ip(r), uid)
                try:
                    if request_json['currency'].upper() in currency_list:
                        try:
                            price = await r.app['rdata'].hget("prices", f"{price_prefix}-" + request_json['currency'].lower())
                            reply = json.dumps({
                                'currency': request_json['currency'].lower(),
                                'price': str(price)
                            })
                            ret = reply
                        except Exception:
                            log.server_logger.error(
                                'price data error, unable to get price;%s;%s', util.get_request_ip(r), uid)
                            ret = json.dumps({
                                'error':'price data error - unable to get price'
                            })
                    else:
                        log.server_logger.error(
                            'price data error, unknown currency;%s;%s', util.get_request_ip(r), uid)
                        ret = json.dumps({
                            'error':'unknown currency'
                        })
                except Exception as e:
                    log.server_logger.error('price data error;%s;%s;%s', str(e), util.get_request_ip(r), uid)
                    ret = json.dumps({
                        'error':'price data error',
                        'details':str(e)
                    })
            # rpc: account_check
            elif request_json['action'] == "account_check":
                log.server_logger.info('account check request;%s;%s', util.get_request_ip(r), uid)
                try:
                    response = await rpc.rpc_accountcheck(r, uid, request_json['account'])
                    ret = json.dumps(response)
                except Exception as e:
                    log.server_logger.error('account check error;%s;%s;%s', str(e), util.get_request_ip(r), uid)
                    ret = json.dumps({
                        'error': 'account check error',
                        'details': str(e)
                    })
            # rpc: process
            elif request_json['action'] == "process":
                try:
                    do_work = False
                    if 'do_work' in request_json and request_json['do_work'] == True:
                        do_work = True
                    subtype = None
                    if 'subtype' in request_json:
                        subtype = request_json['subtype']
                    if 'json_block' in request_json and request_json['json_block']:
                        sblock = request_json['block']
                    else:
                        sblock = json.loads(request_json['block'])
                    reply = await rpc.process_defer(r, uid, sblock, do_work, subtype=subtype)
                    if reply is None:
                        raise Exception
                    ret = json.dumps(reply)
                except Exception as e:
                    log.server_logger.error('process rpc error;%s;%s;%s;User-Agent:%s',
                        str(e), util.get_request_ip(r), uid, str(r.headers.get('User-Agent')))
                    ret = json.dumps({
                        'error':'process rpc error',
                        'details':str(e)
                    })
            # rpc: receivable / deprecated: pending v23.0
            elif request_json['action'] == "receivable" or request_json['action'] == "pending":
                try:
                    # get threshold preference:
                    if 'threshold' in request_json and 'account' in request_json:
                        if request_json['threshold'] is not None and request_json['account'] is not None:
                            # set the min_receive at account
                            print("Setting threshold for account:", request_json['account'], request_json['threshold'])
                            await r.app['rdata'].hset("account_min_raw", request_json['account'], request_json['threshold'])

                    reply = await rpc.pending_defer(r, uid, request_json)
                    if reply is None:
                        raise Exception
                    ret = json.dumps(reply)
                except Exception as e:
                    log.server_logger.error('receivable rpc error;%s;%s;%s;User-Agent:%s', str(
                        e), util.get_request_ip(r), uid, str(r.headers.get('User-Agent')))
                    ret = json.dumps({
                        'error':'receivable rpc error',
                        'details':str(e)
                    })
    
            elif request_json['action'] == 'account_history':
                if await r.app['rdata'].hget(uid, "account") is None:
                    await r.app['rdata'].hset(uid, "account", json.dumps([request_json['account']]))
                try:
                    response = await rpc.json_post(request_json)
                    if response is None:
                        raise Exception
                    ret = json.dumps(response)
                except Exception as e:
                    log.server_logger.error('rpc error;%s;%s;%s', str(e), util.get_request_ip(r), uid)
                    ret = json.dumps({
                        'error':'account_history rpc error',
                        'details': str(e)
                    })

            # elif request_json['action'] == 'account_balances':
            #     pass
                    
            elif request_json['action'] == 'payment_request':
                # check the signature:
                ret = await validate_signature(request_json.get("requesting_account"), request_json.get("request_signature"), request_json.get("request_nonce"))
                if ret == None:
                    ret = await push_payment_request(r, request_json.get("account"), request_json.get("amount_raw"), request_json.get("requesting_account"), request_json.get("memo_enc"), request_json.get("local_uuid"))
                    if ret == None:
                        ret = json.dumps({
                            'success':'payment request sent',
                        })
    
            elif request_json['action'] == 'payment_ack':

                ret = await push_payment_ack(r, request_json["uuid"], request_json["account"], request_json["requesting_account"])
                if ret == None:
                    ret = json.dumps({
                        'success':'payment_ack sent',
                    })
                # # send again to the sender:
                # ret = await push_payment_ack(r, request_json["uuid"], request_json["requesting_account"], request_json["requesting_account"])
                # if ret == None:
                #     ret = json.dumps({
                #         'success':'payment_ack sent',
                #     })
            
            elif request_json['action'] == 'payment_memo':
                # check the signature:
                ret = await validate_signature(request_json.get("requesting_account"), request_json.get("request_signature"), request_json.get("request_nonce"))

                if ret == None:
                    ret = await push_payment_memo(r, request_json.get("account"), request_json.get("requesting_account"), request_json.get("memo_enc"), request_json.get("block"), request_json.get("local_uuid"))
                    if ret == None:
                        ret = json.dumps({
                            'success':'payment memo sent',
                        })

            elif request_json['action'] == 'payment_message':
                # check the signature:
                ret = await validate_signature(request_json.get("requesting_account"), request_json.get("request_signature"), request_json.get("request_nonce"))
                if ret == None:
                    ret = await push_payment_message(r, request_json.get("account"), request_json.get("requesting_account"), request_json.get("memo_enc"), request_json.get("local_uuid"))
                    if ret == None:
                        # todo: save the message struct for re-sending later:

                        ret = json.dumps({
                            'success':'payment memo sent',
                        })
            elif request_json['action'] == 'gift_split_create':

                # # check the signature:
                # ret = await validate_signature(request_json.get("requesting_account"), request_json.get("request_signature"), request_json.get("request_nonce"))
                # if ret == None:
                #     pass

                ret = await gift_split_create(r, request_json.get("seed"), request_json.get("split_amount_raw"), request_json.get("memo"), request_json.get("requesting_account"))
                if ret != None:
                    ret = json.dumps({
                        'success': True,
                        'link': ret["link"],
                        'gift_data': ret["gift_data"],
                    })
            elif request_json['action'] == 'gift_info':
                ret = await gift_info(r, request_json.get("gift_uuid"), request_json.get("requesting_account"), request_json.get("requesting_device_uuid"))
            elif request_json['action'] == 'gift_claim':
                ret = await gift_claim(r, request_json.get("gift_uuid"), request_json.get("requesting_account"), request_json.get("requesting_device_uuid"))
            
            # rpc: fallthrough and error catch
            else:
                try:
                    response = await rpc.json_post(request_json)
                    if response is None:
                        raise Exception
                    ret = json.dumps(response)
                except Exception as e:
                    log.server_logger.error('rpc error;%s;%s;%s', str(e), util.get_request_ip(r), uid)
                    ret = json.dumps({
                        'error':'rpc error',
                        'details': str(e)
                    })
    except Exception as e:
        log.server_logger.exception('uncaught error;%s;%s', util.get_request_ip(r), uid)
        ret = json.dumps({
            'error':'general error',
            'details':str(sys.exc_info())
        })
    finally:
        r.app['active_messages'].remove(message)
        return ret

async def websocket_handler(r : web.Request):
    """Handler for websocket connections and messages"""

    ws = web.WebSocketResponse()
    await ws.prepare(r)

    # Connection Opened
    ws.id = str(uuid.uuid4())
    r.app['clients'][ws.id] = ws
    log.server_logger.info('new connection;%s;%s;User-Agent:%s', util.get_request_ip(r), ws.id, str(r.headers.get('User-Agent')))

    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                if msg.data == 'close':
                    await ws.close()
                else:
                    reply = await handle_user_message(r, msg.data, ws=ws)
                    if reply is not None:
                        log.server_logger.debug('Sending response %s to %s', reply, util.get_request_ip(r))
                        await ws.send_str(reply)
            elif msg.type == WSMsgType.CLOSE:
                log.server_logger.info('WS Connection closed normally')
                break
            elif msg.type == WSMsgType.ERROR:
                log.server_logger.info('WS Connection closed with error %s', ws.exception())
                break

        log.server_logger.info('WS connection closed normally')
    except Exception:
        log.server_logger.exception('WS Closed with exception')
    finally:
        if ws.id in r.app['clients']:
            del r.app['clients'][ws.id]
        for acct in r.app['subscriptions']:
            if ws.id in r.app['subscriptions'][acct]:
                if len(r.app['subscriptions'][acct]) == 1:
                    del r.app['subscriptions'][acct]
                    break
                else:
                    r.app['subscriptions'][acct].remove(ws.id)
                    break
        await ws.close()

    return ws

async def http_api(r: web.Request):
    try:
        request_json = await r.json()
        reply = await handle_user_message(r, json.dumps(request_json))
        if reply is not None:
            return web.json_response(data=json.loads(reply))
        else:
            return web.json_response(data={'error':'bad request'})
    except Exception:
        log.server_logger.exception("received exception in http_api")
        return web.HTTPInternalServerError(reason=f"Something went wrong {str(sys.exc_info())}")

async def alerts_api(r: web.Request):
    return web.json_response(data=get_active_alert(r.match_info["lang"]))

async def funding_api(r: web.Request):
    alerts = get_active_funding(r.match_info["lang"])

    for i in range(len(alerts)):
        if "address" in alerts[i]:
            balance_raw = await r.app['rdata'].hget("funding_balances", alerts[i]["address"])
            if balance_raw is not None:
                alerts[i]["current_amount_raw"] = balance_raw

    return web.json_response(data=alerts)


async def handle_block_handoff(r, request_json):
    if request_json['block'] == None:
        return json.dump({
            'error':'no block specified',
        })
    block = request_json['block']
    resp = await rpc.process_defer(r, "fake_uid", block, True, subtype="send")
    
    if resp is None:
        return json.dumps({
            'error':'no response from rpc',
        })
    
    if (resp["hash"] is not None):
        # success:
        return json.dumps({
            "status": 0,
            "message": "Thank you for your contribution!",
            "label": "Donation: " + resp["hash"],
        })
    return resp

async def handoff_api(r: web.Request):

    try:
        request_json = await r.json()
        reply = await handle_block_handoff(r, request_json)
        if reply is not None:
            return web.json_response(data=json.loads(reply))
        else:
            return web.json_response(data={"status": 8, "message": "Bad request"})
    except Exception:
        log.server_logger.exception("received exception in http_api")
        return web.HTTPInternalServerError(reason=f"Something went wrong {str(sys.exc_info())}")


    # return web.json_response(data={})


async def branch_create_link(paperWalletSeed, paperWalletAccount, memo, fromAddress, amountRaw, giftUUID):
    url = "https://api2.branch.io/v1/url"
    headers = {'Content-Type': 'application/json'}

    global branch_api_key

    data = json.dumps({
    "branch_key": branch_api_key,
    "channel": f"nautilus-backend",
    "feature": f"splitgift",
    "stage": "new share",
    "data":{
        "seed": f"{paperWalletSeed}",
        "address": f"{paperWalletAccount}",
        "memo": f"{memo}",
        "senderAddress": f"{fromAddress}",
        "signature": f"sig",
        "nonce": f"nonce",
        "from_address": f"{fromAddress}",
        "amount_raw": f"{amountRaw}",
        "gift_uuid": f"{giftUUID}",
        "$canonical_identifier": f"server/splitgift/{paperWalletSeed}",
        "$og_title":f"Nautilus Gift Card",
        "$og_description":f"Get the app to open this gift card!",
     }})

    resp = requests.post(url, headers=headers, data=data)
    return resp

async def gift_api_get(r: web.Request):

    # get the gift data from the db
    giftData = await r.app['rdata'].hget("gift_data", r.match_info["gift_uuid"])
    giftData = json.loads(giftData)
    giftUUID = giftData.get("gift_uuid")
    seed = giftData.get("seed")
    fromAddress = giftData.get("from_address")
    splitAmountRaw = giftData.get("split_amount_raw")
    memo = giftData.get("memo")

    # check if a link already exists:
    splitID = util.get_request_ip(r) + nonce_separator + giftUUID
    linkData = await r.app['rdata'].hget("split_gifts", splitID)
    if linkData != None and json.loads(linkData).get("link") != None:
        return web.HTTPTemporaryRedirect(json.loads(linkData).get("link"))

    if giftUUID == None:
        return web.json_response(data={"error": "gift not found!"})

    giftSeed = seed
    giftAccount = generate_account_id(giftSeed, 0).replace("xrb_", "nano_")
    giftPrivateKey = generate_account_private_key(giftSeed, 0)

    # generate new seed and address:
    paperWalletSeed = generate_seed()
    paperWalletAccount = generate_account_id(paperWalletSeed, 0).replace("xrb_", "nano_")
    # paperWalletPrivateKey = generate_account_private_key(paperWalletSeed, 0)

    global branch_api_key

    if branch_api_key == None:
        return web.json_response(data={"error": "branch_api_key not set"})

    # create the branch link, then load the private key using the seed from the db:
    branchResponse = await branch_create_link(paperWalletSeed, paperWalletAccount, memo, fromAddress, amountRaw=splitAmountRaw)

    if branchResponse == None or branchResponse.status_code != 200:
        # error creating link:
        return web.json_response(data={"error": "error creating branch link"})
    
    # send to the paper wallet from the paper wallet seed:

    # receive any receivable funds from the paper wallet first:

    giftWalletBalanceInt = None
    
    # get account_info:
    response = await rpc.json_post({"action": "account_info", "account": giftAccount})
    account_not_opened = False
    if response.get("error") == "Account not found":
        account_not_opened = True
    elif response.get("error") != None:
        return web.json_response(data=json.dumps({"error": response.get("error")}))
    else:
        giftWalletBalanceInt = int(response.get("balance"))

    frontier = None
    if not account_not_opened:
        frontier = response.get("frontier")
    
    # get the receivable blocks:
    receivable_resp = await rpc.json_post({"action": "receivable", "source": True, "count": 10, "include_active": True, "account": giftAccount})
    if receivable_resp.get("blocks") == "":
        receivable_resp["blocks"] = {}
    
    # receive each block:
    for hash in receivable_resp.get("blocks").keys():
        item = receivable_resp["blocks"][hash]
        if (frontier != None):
            giftWalletBalanceInt = int(item.get("amount"))
            receiveBlock = {
                "type": "state",
                "account": giftAccount,
                "previous": frontier,
                "representative": "nano_38713x95zyjsqzx6nm1dsom1jmm668owkeb9913ax6nfgj15az3nu8xkx579",
                "balance": giftWalletBalanceInt,
                "link": hash,
                "link_as_account": get_account_id(public_key=hash).replace("xrb_", "nano_")
            }
            signature = nanopy.sign(key=giftPrivateKey, block=receiveBlock)
            receiveBlock["signature"] = signature
            
            resp = await rpc.process_defer(r, "fake_uid", receiveBlock, True, subtype="receive")
            if resp.get("hash") != None:
                frontier = resp.get("hash")
                # totalTransferred += BigInt.parse(item.amount!)
        else:
            giftWalletBalanceInt = int(item.get("amount"))
            openBlock = {
                "type": "state",
                "account": giftAccount,
                "previous": "0000000000000000000000000000000000000000000000000000000000000000",
                "representative": "nano_38713x95zyjsqzx6nm1dsom1jmm668owkeb9913ax6nfgj15az3nu8xkx579",
                "balance": giftWalletBalanceInt,
                "link": hash,
                "link_as_account": get_account_id(public_key=hash).replace("xrb_", "nano_")
            }
            signature = nanopy.sign(key=giftPrivateKey, block=openBlock)
            openBlock["signature"] = signature
            
            resp = await rpc.process_defer(r, "fake_uid", openBlock, True, subtype="open")
            if resp.get("hash") != None:
                frontier = resp.get("hash")
                # totalTransferred += BigInt.parse(item.amount!);
    
    # Hack that waits for blocks to be confirmed
    time.sleep(1)


    # get the gift frontier:
    giftFrontier = frontier

    frontiers_resp = await rpc.json_post({"action": "frontiers", "count": 1, "account": giftAccount})
    if frontiers_resp.get("frontiers") == "":
        giftFrontier = frontier
    else:
        returnedFrontiers = frontiers_resp.get("frontiers")
        for addr in returnedFrontiers.keys():
            giftFrontier = returnedFrontiers[addr]
            break
    
    # send the split amount to the paper wallet:
    # send from giftSeed -> paperWalletAccount

    if splitAmountRaw == None:
        return web.json_response(data={"error": "splitAmountRaw is None"})

    # get account_info:
    if giftWalletBalanceInt == None:
        return web.json_response(data=json.dumps({"error": "giftWalletBalanceInt shouldn't be None"}))
    elif giftWalletBalanceInt == 0:
        # the gift wallet is empty, so we can't send anything:
        return web.json_response(data=json.dumps({"error": "Gift wallet is empty!"}))

    newBalanceRaw = str(int(giftWalletBalanceInt) - int(splitAmountRaw))

    if newBalanceRaw == None:
        return web.json_response(data={"error": "newBalanceRaw is None"})
    elif int(newBalanceRaw) < 0:
        # send whatever is left in the gift wallet:
        newBalanceRaw = "0"

    sendBlock = {
        "type": "state",
        "account": giftAccount,
        "previous": giftFrontier,
        "representative": "nano_38713x95zyjsqzx6nm1dsom1jmm668owkeb9913ax6nfgj15az3nu8xkx579",
        "balance": newBalanceRaw,
        "destination": paperWalletAccount,
        "link": get_account_public_key(account_id=paperWalletAccount),
        "link_as_account": paperWalletAccount
    }
    signature = nanopy.sign(key=giftPrivateKey, block=sendBlock)
    sendBlock["signature"] = signature

    resp = await rpc.process_defer(r, "fake_uid", sendBlock, True, subtype="send")
    
    if resp.get("hash") == None:
        return web.json_response(data={"error": "error sending to paper wallet: " + str(resp)})
    else:
        # cache the paper wallet link:
        branchLink = branchResponse.json().get("url")

        splitLinkData = json.dumps({
            "gift_uuid": giftUUID,
            "link": branchLink,
            "paper_wallet_account": paperWalletAccount,
            "paper_wallet_seed": paperWalletSeed,
        })
        splitID = util.get_request_ip(r) + nonce_separator + giftUUID
        await r.app['rdata'].hset("split_gifts", splitID, splitLinkData)
        return web.HTTPTemporaryRedirect(branchLink)

# async def gift_split_create(r: web.Request, seed, splitAmountRaw, memo, fromAddress):

#     giftUUID = str(uuid.uuid4())[-12:]
#     giftData = json.dumps({
#         "seed": seed,
#         "split_amount_raw": splitAmountRaw,
#         "memo": memo,
#         "from_address": fromAddress,
#         "gift_uuid": giftUUID,
#     })
#     await r.app['rdata'].hset("gift_data", giftUUID, giftData)
#     link = f"https://nautilus.perish.co/gift/{giftUUID}"
#     return {"link": link, "gift_data": giftData}




async def gift_split_create(r: web.Request, seed, splitAmountRaw, memo, fromAddress):

    giftUUID = str(uuid.uuid4())[-12:]
    giftData = json.dumps({
        "seed": seed,
        "split_amount_raw": splitAmountRaw,
        "memo": memo,
        "from_address": fromAddress,
        "gift_uuid": giftUUID,
    })
    await r.app['rdata'].hset("gift_data", giftUUID, giftData)

    if (int(splitAmountRaw) > 1000000000000000000000000000000000):
        return web.json_response(data={"error": "splitAmountRaw is too large"})
    
    paperWalletAccount = generate_account_id(seed, 0).replace("xrb_", "nano_")

    branchResponse = await branch_create_link("", "", memo, fromAddress, amountRaw=splitAmountRaw, giftUUID=giftUUID)
    if branchResponse == None or branchResponse.status_code != 200:
        return {"error": "error creating branch link"}
    
    branchLink = branchResponse.json().get("url")
    return {"link": branchLink, "gift_data": giftData}


async def gift_info(r: web.Request, giftUUID, requestingAccount, requestingDeviceUUID):

    # check if the gift exists:
    giftData = await r.app['rdata'].hget("gift_data", giftUUID)
    if giftData == None:
        return json.dumps({"error": "gift does not exist"})
    giftData = json.loads(giftData)

    if requestingDeviceUUID == None or requestingDeviceUUID == "":
        return json.dumps({"error": "requestingDeviceUUID is None"})
    
    # check if it was claimed by this user:
    # splitID = util.get_request_ip(r) + nonce_separator + giftUUID + nonce_separator + requestingAccount
    splitID = requestingDeviceUUID + nonce_separator + giftUUID
    claimed = await r.app['rdata'].hget("gift_claims", splitID)
    if claimed != None:
        return json.dumps({"error": "gift has already been claimed"})

    # check the balance of the gift wallet:
    giftWalletSeed = giftData.get("seed")
    giftWalletAccount = generate_account_id(giftWalletSeed, 0).replace("xrb_", "nano_")

    # giftWalletBalance = await rpc.json_post({"action": "account_balance", "account": giftWalletAccount})

    amount = giftData.get("split_amount_raw")
    if amount == None:
        amount = giftData.get("amount_raw")

    returnable = {
        "gift_uuid": giftUUID,
        "amount_raw": amount,
        "memo": giftData.get("memo"),
        "from_address": giftData.get("from_address"),
    }

    # if giftWalletBalance.get("balance") != None:
    #     returnable["gift_wallet_balance"] = giftWalletBalance.get("balance")

    return json.dumps({"success": True, "gift_data": returnable})

async def gift_claim(r: web.Request, giftUUID, requestingAccount, requestingDeviceUUID):

    # get the gift data from the db
    giftData = await r.app['rdata'].hget("gift_data", giftUUID)
    giftData = json.loads(giftData)
    giftUUID = giftData.get("gift_uuid")
    seed = giftData.get("seed")
    fromAddress = giftData.get("from_address")
    splitAmountRaw = giftData.get("split_amount_raw")
    amountRaw = giftData.get("amount_raw")
    memo = giftData.get("memo")

    sendAmountRaw = None
    if splitAmountRaw != None:
        sendAmountRaw = splitAmountRaw
    elif amountRaw != None:
        sendAmountRaw = amountRaw

    if sendAmountRaw == None:
        return json.dumps({"error": "sendAmountRaw is None"})


    # check the gift card balance and receive any incoming funds:
    if giftUUID == None:
        return {"error": "gift not found!"}

    if requestingDeviceUUID == None or requestingDeviceUUID == "":
        return json.dumps({"error": "requestingDeviceUUID is None"})

    # check if it was claimed by this user:
    # splitID = util.get_request_ip(r) + nonce_separator + giftUUID + nonce_separator + requestingAccount
    splitID = requestingDeviceUUID + nonce_separator + giftUUID
    claimed = await r.app['rdata'].hget("gift_claims", splitID)
    if claimed != None:
        return json.dumps({"error": "gift has already been claimed"})

    giftSeed = seed
    giftAccount = generate_account_id(giftSeed, 0).replace("xrb_", "nano_")
    giftPrivateKey = generate_account_private_key(giftSeed, 0)

    # receive any receivable funds from the paper wallet first:

    giftWalletBalanceInt = None
    
    # get account_info:
    response = await rpc.json_post({"action": "account_info", "account": giftAccount})
    account_not_opened = False
    if response.get("error") == "Account not found":
        account_not_opened = True
    elif response.get("error") != None:
        return json.dumps({"error": response.get("error")})
    else:
        giftWalletBalanceInt = int(response.get("balance"))

    frontier = None
    if not account_not_opened:
        frontier = response.get("frontier")
    
    # get the receivable blocks:
    receivable_resp = await rpc.json_post({"action": "receivable", "source": True, "count": 10, "include_active": True, "account": giftAccount})
    if receivable_resp.get("blocks") == "":
        receivable_resp["blocks"] = {}
    
    # receive each block:
    for hash in receivable_resp.get("blocks").keys():
        item = receivable_resp["blocks"][hash]
        if (frontier != None):
            giftWalletBalanceInt = int(item.get("amount"))
            receiveBlock = {
                "type": "state",
                "account": giftAccount,
                "previous": frontier,
                "representative": "nano_38713x95zyjsqzx6nm1dsom1jmm668owkeb9913ax6nfgj15az3nu8xkx579",
                "balance": giftWalletBalanceInt,
                "link": hash,
                "link_as_account": get_account_id(public_key=hash).replace("xrb_", "nano_")
            }
            signature = nanopy.sign(key=giftPrivateKey, block=receiveBlock)
            receiveBlock["signature"] = signature
            
            resp = await rpc.process_defer(r, "fake_uid", receiveBlock, True, subtype="receive")
            if resp.get("hash") != None:
                frontier = resp.get("hash")
                # totalTransferred += BigInt.parse(item.amount!)
        else:
            giftWalletBalanceInt = int(item.get("amount"))
            openBlock = {
                "type": "state",
                "account": giftAccount,
                "previous": "0000000000000000000000000000000000000000000000000000000000000000",
                "representative": "nano_38713x95zyjsqzx6nm1dsom1jmm668owkeb9913ax6nfgj15az3nu8xkx579",
                "balance": giftWalletBalanceInt,
                "link": hash,
                "link_as_account": get_account_id(public_key=hash).replace("xrb_", "nano_")
            }
            signature = nanopy.sign(key=giftPrivateKey, block=openBlock)
            openBlock["signature"] = signature
            
            resp = await rpc.process_defer(r, "fake_uid", openBlock, True, subtype="open")
            if resp.get("hash") != None:
                frontier = resp.get("hash")
                # totalTransferred += BigInt.parse(item.amount!);
    
    # Hack that waits for blocks to be confirmed
    time.sleep(4)


    # get the gift frontier:
    giftFrontier = frontier

    frontiers_resp = await rpc.json_post({"action": "frontiers", "count": 1, "account": giftAccount})
    if frontiers_resp.get("frontiers") == "":
        giftFrontier = frontier
    else:
        returnedFrontiers = frontiers_resp.get("frontiers")
        for addr in returnedFrontiers.keys():
            giftFrontier = returnedFrontiers[addr]
            break

    # get account_info (again) so we can be 100% sure of the balance:
    giftWalletBalanceInt = None
    response = await rpc.json_post({"action": "account_info", "account": giftAccount})
    if response.get("error") != None:
        return json.dumps({"error": response.get("error")})
    else:
        giftWalletBalanceInt = int(response.get("balance"))
    
    # send sendAmountRaw to the requester:
    # get account_info:
    if giftWalletBalanceInt == None:
        return {"error": "giftWalletBalanceInt shouldn't be None"}
    elif giftWalletBalanceInt == 0:
        # the gift wallet is empty, so we can't send anything:
        return {"error": "Gift wallet is empty!"}

    newBalanceRaw = str(int(giftWalletBalanceInt) - int(sendAmountRaw))

    if newBalanceRaw == None:
        return {"error": "newBalanceRaw is None"}
    elif int(newBalanceRaw) < 0:
        # send whatever is left in the gift wallet:
        newBalanceRaw = "0"

    # create the send block:
    sendBlock = {
        "type": "state",
        "account": giftAccount,
        "previous": giftFrontier,
        "representative": "nano_38713x95zyjsqzx6nm1dsom1jmm668owkeb9913ax6nfgj15az3nu8xkx579",
        "balance": newBalanceRaw,
        "destination": requestingAccount,
        "link": get_account_public_key(account_id=requestingAccount),
        "link_as_account": requestingAccount
    }
    signature = nanopy.sign(key=giftPrivateKey, block=sendBlock)
    sendBlock["signature"] = signature

    resp = await rpc.process_defer(r, "fake_uid", sendBlock, True, subtype="send")
    
    if resp.get("hash") == None:
        return json.dumps({"error": "error sending to paper wallet: " + str(resp)})
    
    # cache the response for this UUID:
    await r.app['rdata'].hset("gift_claims", splitID, "claimed")

    return json.dumps({"success": True})

async def callback_ws(app: web.Application, data: dict):   
    if 'block' in data and 'link_as_account' in data['block']:
        account = data['block']['link_as_account']
        if app['subscriptions'].get(account):
            log.server_logger.info("Pushing to clients %s", str(app['subscriptions'][account]))
            for sub in app['subscriptions'][account]:
                if sub in app['clients']:
                    if data['block']['subtype'] == 'send':
                        data['is_send'] = 'true'
                        await app['clients'][sub].send_str(json.dumps(data))
        
        # push notifications:
        # await callback_retro(data, app)

        # # Send to natrium donations page
        # if data['block']['subtype'] == 'send' and link == 'nano_1natrium1o3z5519ifou7xii8crpxpk8y65qmkih8e8bpsjri651oza8imdd':
        #     log.server_logger.info('Detected send to natrium account')
        #     if 'amount' in data:
        #         log.server_logger.info(f'emitting donation event for amount: {data["amount"]}')
        #         await sio.emit('donation_event', {'amount':data['amount']})

# allow sends with the original uuid if they are valid:
# TODO:
async def check_local_uuid(local_uuid):
    new_uuid = str(uuid.uuid4())
    if local_uuid is None:
        return new_uuid
    # TODO:
    return new_uuid

# todo:
# async def store_request(r, uuid, data):
#     await r.app['rdata'].set(uuid, json.dumps(data))
#     await r.app['rdata'].expire(uuid, 60 * 60 * 24)
#     return uuid


async def validate_signature(requesting_account, request_signature, request_nonce):
    ret = None
    # check if the nonce is valid
    req_account_bin = unhexlify(util.address_decode(requesting_account))

    nonce_fields = request_nonce.split(nonce_separator)
    # make sure the nonce is recent:
    request_epoch_time = int(nonce_fields[0], 16)

    current_epoch_time = int(time.time())
    if (current_epoch_time - request_epoch_time) > nonce_timeout_seconds:
        # nonce is too old
        ret = json.dumps({
            'error':'nonce error',
            'details': 'nonce is too old'
        })
        return ret

    vk = VerifyingKey(req_account_bin)
    try:
        vk.verify(
            sig=unhexlify(request_signature),
            msg=unhexlify(request_nonce),
        )
    except:
        ret = json.dumps({
            'error':'sig error',
            'details': 'invalid signature'
        })
    return ret

async def push_payment_request(r, account, amount_raw, requesting_account, memo_enc, local_uuid):

    if fcm_api_key is None:
        return json.dumps({
            'error':'fcm token error',
            'details': "no_api_key"
        })
    
    fcm_tokens_v2 = set(await get_fcm_tokens(account, r, v2=True))
    if (fcm_tokens_v2 is None or len(fcm_tokens_v2) == 0):
        return json.dumps({
            'error':'fcm token error',
            'details': "no_tokens"
        })

    # get username if it exists:
    shorthand_account = await r.app['rdata'].hget("usernames", f"{requesting_account}")
    if shorthand_account == None:
        # set username to abbreviated account name:
        shorthand_account = requesting_account[0:12]
    else:
        shorthand_account = "@" + shorthand_account

    # push notifications
    fcm = aiofcm.FCM(fcm_sender_id, fcm_api_key)

    request_uuid = await check_local_uuid(local_uuid)
    request_time = str(int(time.time()))

    # Send notification with generic title, send amount as body. App should have localizations and use this information at its discretion
    notification_title = f"Request for {util.raw_to_nano(int(amount_raw))} {'NANO' if not banano_mode else 'BANANO'} from {shorthand_account}"
    notification_body = f"Open Nautilus to pay this request."
    for t2 in fcm_tokens_v2:
        message = aiofcm.Message(
            device_token = t2,
            notification = {
                "title":notification_title,
                "body":notification_body,
                "sound":"default",
                "tag": account
            },
            data = {
                "click_action": "FLUTTER_NOTIFICATION_CLICK",
                "account": account,
                "payment_request": True,
                "uuid": request_uuid,
                "local_uuid": local_uuid,
                "memo_enc": str(memo_enc),
                "amount_raw": str(amount_raw),
                "requesting_account": requesting_account,
                "requesting_account_shorthand": shorthand_account,
                "request_time": request_time
            },
            priority=aiofcm.PRIORITY_HIGH,
            content_available=True
        )
        await fcm.send_message(message)

    # @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    # also push to the requesting account, so they add the account to their list of payment requests
    # @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

    fcm_tokens_v2 = set(await get_fcm_tokens(requesting_account, r, v2=True))
    if (fcm_tokens_v2 is None or len(fcm_tokens_v2) == 0):
        return json.dumps({
            'error':'fcm token error',
            'details': "no_tokens"
        })

    # push notifications
    fcm = aiofcm.FCM(fcm_sender_id, fcm_api_key)

    for t2 in fcm_tokens_v2:
        message = aiofcm.Message(
            device_token = t2,
            data = {
                # "click_action": "FLUTTER_NOTIFICATION_CLICK",
                "account": account,
                "payment_record": True,
                "is_request": True,
                "memo_enc": str(memo_enc),
                "uuid": request_uuid,
                "local_uuid": local_uuid,
                "amount_raw": str(amount_raw),
                "requesting_account": requesting_account,
                "requesting_account_shorthand": shorthand_account,
                "request_time": request_time
            },
            priority=aiofcm.PRIORITY_HIGH,
            content_available=True
        )
        await fcm.send_message(message)

async def push_payment_message(r, account, requesting_account, memo_enc, local_uuid):

    if fcm_api_key is None:
        return json.dumps({
            'error':'fcm token error',
            'details': "no_api_key"
        })
    
    fcm_tokens_v2 = set(await get_fcm_tokens(account, r, v2=True))
    if (fcm_tokens_v2 is None or len(fcm_tokens_v2) == 0):
        return json.dumps({
            'error':'fcm token error',
            'details': "no_tokens"
        })

    # get username if it exists:
    shorthand_account = await r.app['rdata'].hget("usernames", f"{requesting_account}")
    if shorthand_account == None:
        # set username to abbreviated account name:
        shorthand_account = requesting_account[0:12]
    else:
        shorthand_account = "@" + shorthand_account

    # push notifications
    fcm = aiofcm.FCM(fcm_sender_id, fcm_api_key)

    request_uuid = await check_local_uuid(local_uuid)
    request_time = str(int(time.time()))

    # Send notification with generic title, send amount as body. App should have localizations and use this information at its discretion
    notification_title = f"Message from {shorthand_account}"
    notification_body = f"Open Nautilus to view."
    for t2 in fcm_tokens_v2:
        message = aiofcm.Message(
            device_token = t2,
            notification = {
                "title":notification_title,
                "body":notification_body,
                "sound":"default",
                "tag": account
            },
            data = {
                "click_action": "FLUTTER_NOTIFICATION_CLICK",
                "account": account,
                "payment_message": True,
                "uuid": request_uuid,
                "local_uuid": local_uuid,
                "memo_enc": str(memo_enc),
                "requesting_account": requesting_account,
                "requesting_account_shorthand": shorthand_account,
                "request_time": request_time
            },
            priority=aiofcm.PRIORITY_HIGH,
            content_available=True
        )
        await fcm.send_message(message)

    # @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    # also push to the requesting account, so they add the account to their list of payment requests
    # @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

    fcm_tokens_v2 = set(await get_fcm_tokens(requesting_account, r, v2=True))
    if (fcm_tokens_v2 is None or len(fcm_tokens_v2) == 0):
        return json.dumps({
            'error':'fcm token error',
            'details': "no_tokens"
        })

    # push notifications
    fcm = aiofcm.FCM(fcm_sender_id, fcm_api_key)

    for t2 in fcm_tokens_v2:
        message = aiofcm.Message(
            device_token = t2,
            data = {
                # "click_action": "FLUTTER_NOTIFICATION_CLICK",
                "account": account,
                "payment_record": True,
                "is_message": True,
                "memo_enc": str(memo_enc),
                "uuid": request_uuid,
                "local_uuid": local_uuid,
                "requesting_account": requesting_account,
                "requesting_account_shorthand": shorthand_account,
                "request_time": request_time
            },
            priority=aiofcm.PRIORITY_HIGH,
            content_available=True
        )
        await fcm.send_message(message)
    return None


async def push_payment_ack(r, request_uuid, account, requesting_account):

    if fcm_api_key is None:
        return json.dumps({
            'error':'fcm token error',
            'details': "no_api_key"
        })
    
    fcm_tokens_v2 = set(await get_fcm_tokens(account, r, v2=True))
    if (fcm_tokens_v2 is None or len(fcm_tokens_v2) == 0):
        return json.dumps({
            'error':'fcm token error',
            'details': "no_tokens"
        })
    
    # push notifications
    fcm = aiofcm.FCM(fcm_sender_id, fcm_api_key)

    # Send notification
    for t2 in fcm_tokens_v2:
        message = aiofcm.Message(
            device_token = t2,
            data = {
                # "click_action": "FLUTTER_NOTIFICATION_CLICK",
                "account": account,
                "payment_ack": True,
                "uuid": request_uuid,
                "requesting_account": requesting_account
            },
            priority=aiofcm.PRIORITY_HIGH,
            content_available=True
        )
        await fcm.send_message(message)
    return None

async def push_payment_memo(r, account, requesting_account, memo_enc, block, local_uuid):

    if fcm_api_key is None:
        return json.dumps({
            'error':'fcm token error',
            'details': "no_api_key"
        })
    
    fcm_tokens_v2 = set(await get_fcm_tokens(account, r, v2=True))
    if (fcm_tokens_v2 is None or len(fcm_tokens_v2) == 0):
        return json.dumps({
            'error':'fcm token error',
            'details': "no_tokens"
        })
    
    # push notifications
    fcm = aiofcm.FCM(fcm_sender_id, fcm_api_key)

    request_uuid = await check_local_uuid(local_uuid)
    request_time = str(int(time.time()))

    # send memo to the recipient
    for t2 in fcm_tokens_v2:
        message = aiofcm.Message(
            device_token = t2,
            data = {
                # "click_action": "FLUTTER_NOTIFICATION_CLICK",
                "account": account,
                "requesting_account": requesting_account,
                "payment_memo": True,
                "memo_enc": str(memo_enc),
                "block": str(block),
                "uuid": request_uuid,
                "local_uuid": local_uuid,
                "request_time": request_time
            },
            priority=aiofcm.PRIORITY_HIGH,
            content_available=True
        )
        await fcm.send_message(message)
    # @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    # also push to the requesting account, so they get the uuid
    # @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

    fcm_tokens_v2 = set(await get_fcm_tokens(requesting_account, r, v2=True))
    if (fcm_tokens_v2 is None or len(fcm_tokens_v2) == 0):
        return "no_tokens"

    # push notifications
    fcm = aiofcm.FCM(fcm_sender_id, fcm_api_key)

    for t2 in fcm_tokens_v2:
        message = aiofcm.Message(
            device_token = t2,
            data = {
                # "click_action": "FLUTTER_NOTIFICATION_CLICK",
                "account": account,
                "requesting_account": requesting_account,
                "payment_record": True,
                "is_memo": True,
                "memo_enc": str(memo_enc),
                "uuid": request_uuid,
                "local_uuid": local_uuid,
                "block": str(block),
                # "amount_raw": str(send_amount),
                # "requesting_account": requesting_account,
                # "requesting_account_shorthand": shorthand_account,
                "request_time": request_time
            },
            priority=aiofcm.PRIORITY_HIGH,
            content_available=True
        )
        await fcm.send_message(message)
    return None

async def callback_retro(request_json, app):
    try:
        hash = request_json['hash']
        log.server_logger.debug(f"callback received {hash}")
        # request_json['block'] = json.loads(request_json['block'])

        account = request_json['block']['link_as_account']
        
        # hack bc the structure is weird:
        r = Object()
        r.app = app

        # Push FCM notification if this is a send
        if fcm_api_key is None:
            return web.HTTPOk()
        fcm_tokens_v2 = set(await get_fcm_tokens(account, r, v2=True))
        if (fcm_tokens_v2 is None or len(fcm_tokens_v2) == 0):
            return web.HTTPOk()
        message = {
            "action":"block",
            "hash":request_json['block']['previous']
        }
        response = await rpc.json_post(message)
        if response is None:
            return web.HTTPOk()
        # See if this block was already pocketed
        cached_hash = await r.app['rdata'].get(f"link_{hash}")
        if cached_hash is not None:
            return web.HTTPOk()
        prev_data = response
        prev_data = prev_data['contents'] = json.loads(prev_data['contents'])
        prev_balance = int(prev_data['contents']['balance'])
        cur_balance = int(request_json['block']['balance'])
        send_amount = prev_balance - cur_balance

        min_raw_receive = None
        # check cached pref for min receive amount
        min_raw_receive = await r.app['rdata'].hget("account_min_raw", account)

        if min_raw_receive is None:
            # min_raw_receive = "1000000000000000000000000"
            min_raw_receive = "0"

        # get username if it exists:
        from_account = request_json['block']['account']
        shorthand_account = await r.app['rdata'].hget("usernames", f"{from_account}")
        if shorthand_account == None:
            # set username to abbreviated account name:
            shorthand_account = from_account[0:12]
        else:
            shorthand_account = "@" + shorthand_account

        if int(send_amount) >= int(min_raw_receive):
            # This is a send, push notifications
            fcm = aiofcm.FCM(fcm_sender_id, fcm_api_key)
            # Send notification with generic title, send amount as body. App should have localizations and use this information at its discretion
            notification_title = f"Received {util.raw_to_nano(send_amount)} {'NANO' if not banano_mode else 'BANANO'} from {shorthand_account}"
            notification_body = f"Open Nautilus to view this transaction."
            for t2 in fcm_tokens_v2:
                message = aiofcm.Message(
                    device_token = t2,
                    notification = {
                        "title":notification_title,
                        "body":notification_body,
                        "sound":"default",
                        "tag":account
                    },
                    data = {
                        "click_action": "FLUTTER_NOTIFICATION_CLICK",
                        "account": account,
                        # "memo": request_json['block']['memo']
                    },
                    priority=aiofcm.PRIORITY_HIGH,
                    content_available=True
                )
                await fcm.send_message(message)
        return web.HTTPOk()
    except Exception:
        log.server_logger.exception("received exception in callback")
        return web.HTTPInternalServerError(reason=f"Something went wrong {str(sys.exc_info())}")

async def callback(r : web.Request):
    try:
        request_json = await r.json()
        hash = request_json['hash']
        log.server_logger.debug(f"callback received {hash}")
        request_json['block'] = json.loads(request_json['block'])

        account = request_json['block']['link_as_account']

        # Push FCM notification if this is a send
        if fcm_api_key is None:
            return web.HTTPOk()
        fcm_tokens_v2 = set(await get_fcm_tokens(account, r, v2=True))
        if (fcm_tokens_v2 is None or len(fcm_tokens_v2) == 0):
            return web.HTTPOk()
        # message = {
        #     "action":"block",
        #     "hash":request_json['block']['previous']
        # }
        # response = await rpc.json_post(message)
        # if response is None:
        #     return web.HTTPOk()

        # # See if this block was already pocketed
        # cached_hash = await r.app['rdata'].get(f"link_{hash}")
        # if cached_hash is not None:
        #     return web.HTTPOk()
        
        # # TODO: figure out why the RPC above causes a 500 internal server error:
        # prev_data = response
        # prev_data = prev_data['contents'] = json.loads(prev_data['contents'])
        # prev_balance = int(prev_data['contents']['balance'])
        # cur_balance = int(request_json['block']['balance'])
        # send_amount = prev_balance - cur_balance


        send_amount = int(request_json['amount'])

        min_raw_receive = None
        # check cached pref for min receive amount
        min_raw_receive = await r.app['rdata'].hget("account_min_raw", account)

        if min_raw_receive is None:
            # min_raw_receive = "1000000000000000000000000"
            min_raw_receive = "0"
        
        # get username if it exists:
        from_account = request_json['block']['account']
        shorthand_account = await r.app['rdata'].hget("usernames", f"{from_account}")
        if shorthand_account == None:
            # set username to abbreviated account name:
            shorthand_account = from_account[0:12]
        else:
            shorthand_account = "@" + shorthand_account
        
        if int(send_amount) >= int(min_raw_receive):
            # This is a send, push notifications
            fcm = aiofcm.FCM(fcm_sender_id, fcm_api_key)
            # Send notification with generic title, send amount as body. App should have localizations and use this information at its discretion
            notification_title = f"Received {util.raw_to_nano(send_amount)} {'NANO' if not banano_mode else 'BANANO'} from {shorthand_account}"
            notification_body = f"Open Nautilus to view this transaction."
            for t2 in fcm_tokens_v2:
                message = aiofcm.Message(
                    device_token = t2,
                    notification = {
                        "title":notification_title,
                        "body":notification_body,
                        "sound":"default",
                        "tag":account
                    },
                    data = {
                        "click_action": "FLUTTER_NOTIFICATION_CLICK",
                        "account": account,
                    },
                    priority=aiofcm.PRIORITY_HIGH,
                    content_available=True
                )
                await fcm.send_message(message)
        return web.HTTPOk()
    except Exception:
        log.server_logger.exception("received exception in callback")
        return web.HTTPInternalServerError(reason=f"Something went wrong {str(sys.exc_info())}")

async def send_prices(app):
    """Send price updates to connected clients once per minute"""
    while True:
        # global active_work
        # active_work = set()
        # empty out this set periodically, to ensure clients dont somehow get stuck when an error causes their
        # work not to return
        try:
            if 'clients' in app and len(app['clients']):
                log.server_logger.info('pushing price data to %d connections', len(app['clients']))
                btc = float(await app['rdata'].hget("prices", f"{price_prefix}-btc"))
                if banano_mode:
                    nano = float(await app['rdata'].hget("prices", f"{price_prefix}-nano"))
                for client, ws in list(app['clients'].items()):
                    try:
                        try:
                            currency = app['cur_prefs'][client]
                        except Exception:
                            currency = 'usd'
                        price = float(await app['rdata'].hget("prices", f"{price_prefix}-" + currency.lower()))

                        response = {
                            'currency':currency.lower(),
                            "price":str(price),
                            'btc':str(btc)
                        }
                        if banano_mode:
                            response['nano'] = str(nano)
                        await ws.send_str(json.dumps(response))
                    except Exception:
                        log.server_logger.exception('error pushing prices for client %s', client)
        except Exception:
            log.server_logger.exception("exception pushing price data")
        await asyncio.sleep(60)

async def init_app():
    """ Initialize the main application instance and return it"""
    async def close_redis(app):
        """Close redis connections"""
        log.server_logger.info('Closing redis connections')
        app['rdata'].close()

    async def open_redis(app):
        """Open redis connections"""
        log.server_logger.info("Opening redis connections")
        app['rdata'] = await aioredis.create_redis_pool((redis_host, redis_port),
            db=redis_db, encoding='utf-8', minsize=2, maxsize=15, password=redis_password, ssl=True)
        # redis_url = "rediss://"
        # if redis_username != None:
        #     redis_url += f"{redis_username}:{redis_password}@"
        # redis_url += redis_host
        # if redis_port != None:
        #     redis_url += f":{redis_port}"
        # app['rdata'] = await aioredis.from_url(redis_url, encoding="utf-8", decode_responses=True, db=int(os.getenv('REDIS_DB', '2')), max_connections=15)
        # app['rdata'] = await aioredis.create_connection((redis_host, redis_port), encoding="utf-8", decode_responses=True, db=int(os.getenv('REDIS_DB', '2')), ssl=True)

        # Global vars
        app['clients'] = {} # Keep track of connected clients
        app['last_msg'] = {} # Last time a client has sent a message
        app['active_messages'] = set() # Avoid duplicate messages from being processes simultaneously
        app['cur_prefs'] = {} # Client currency preferences
        app['subscriptions'] = {} # Store subscription UUIDs, this is used for targeting callback accounts
        app['active_work'] = set() # Keep track of active work requests to prevent duplicates

    # Setup logger
    if debug_mode:
        logging.basicConfig(level=logging.DEBUG)
    else:
        root = logging.getLogger('aiohttp.server')
        logging.basicConfig(level=logging.INFO)
        if options.log_to_stdout:
            handler = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter("%(asctime)s;%(levelname)s;%(message)s", "%Y-%m-%d %H:%M:%S %z")
            handler.setFormatter(formatter)
            root.addHandler(handler)
        else:
            handler = WatchedFileHandler(log_file)
            formatter = logging.Formatter("%(asctime)s;%(levelname)s;%(message)s", "%Y-%m-%d %H:%M:%S %z")
            handler.setFormatter(formatter)
            root.addHandler(handler)
            root.addHandler(TimedRotatingFileHandler(log_file, when="d", interval=1, backupCount=100))        

    app = web.Application()
    cors = aiohttp_cors.setup(app, defaults={
        "*": aiohttp_cors.ResourceOptions(
                allow_credentials=True,
                expose_headers="*",
                allow_headers="*",
            )
    })
    # websockets:
    app.add_routes([web.get('/', websocket_handler)]) # All WS requests
    # get node callbacks:
    # old:
    # app.add_routes([web.post('/callback', callback)]) # HTTP Callback from node
    # new (CORS):
    callback_resource = cors.add(app.router.add_resource("/retro"))
    cors.add(callback_resource.add_route("POST", callback))
    # HTTP API
    users_resource = cors.add(app.router.add_resource("/api"))
    cors.add(users_resource.add_route("POST", http_api))

    # BLOCK HANDOFF
    users_resource = cors.add(app.router.add_resource("/handoff"))
    cors.add(users_resource.add_route("POST", handoff_api))

    # alerts:
    alerts_resource = cors.add(app.router.add_resource("/alerts/{lang}"))
    cors.add(alerts_resource.add_route("GET", alerts_api))

    # funding:
    funding_resource = cors.add(app.router.add_resource("/funding/{lang}"))
    cors.add(funding_resource.add_route("GET", funding_api))

    # gift endpoints:
    gift_resource = cors.add(app.router.add_resource("/gift/{gift_uuid}"))
    cors.add(gift_resource.add_route("GET", gift_api_get))

    app.on_startup.append(open_redis)
    app.on_shutdown.append(close_redis)

    return app

app = loop.run_until_complete(init_app())
sio = socketio.AsyncServer(async_mode='aiohttp', cors_allowed_origins='*')
sio.attach(app)

def main():
    """Main application loop"""

    # Periodic price job
    price_task = loop.create_task(send_prices(app))

    # Start web/ws server
    async def start():
        runner = web.AppRunner(app)
        tasks = [

        ]
        await runner.setup()
        if app_path is not None:
            site = web.UnixSite(runner, app_path)
        else:
            site = web.TCPSite(runner, listen_host, listen_port)
        tasks.append(site.start())
        # Websocket
        log.server_logger.info(f"Attempting to open WS connection to {ws_url}")
        ws = WebsocketClient(app, ws_url, callback_ws)
        await ws.setup()
        tasks.append(ws.loop())
        await asyncio.wait(tasks)

    async def end():
        await app.shutdown()

    # Main program
    try:
        loop.run_until_complete(start())
    except KeyboardInterrupt:
        pass
    finally:
        price_task.cancel()
        loop.run_until_complete(end())

    loop.close()

if __name__ == "__main__":
    main()
