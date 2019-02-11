import time
import random
import requests
import json
import hashlib
import rsa
import base64
import re
import datetime
from urllib import parse

WEBAPI_HEADER = {
    "Host": "api.bilibili.com",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.139 Safari/537.36",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8"
}
APPAPI_HEADER = {
    "User-Agent": "Mozilla/5.0 BiliDroid/5.26.3 (bbcallen@gmail.com)",
    "Host": "app.bilibili.com",
}
APP_KEY = "1d8b6e7d45233436"

def _calc_sign(str):
    return hashlib.md5((str + "560c52ccd288fed045859ed18bffd973").encode('utf-8')).hexdigest()

def _calc_pwd(username, password):
    params = { 'appkey': APP_KEY, 'sign': _calc_sign("appkey=" + APP_KEY) }
    response = requests.post("https://passport.bilibili.com/api/oauth2/getKey", data = params)
    key = response.json()['data']['key']
    hash = response.json()['data']['hash']
    pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(key.encode())
    password = base64.b64encode(rsa.encrypt((hash + password).encode('utf-8'), pubkey))
    password = parse.quote_plus(password)
    username = parse.quote_plus(username)
    return username, password

_session = {}
def bilibili_login(username, password):
    user, pwd = _calc_pwd(username, password)
    params = 'appkey=' + APP_KEY + '&password=' + pwd + '&username=' + user
    params += "&sign=" + _calc_sign(params)
    response = requests.post("https://passport.bilibili.com/api/v2/oauth2/login", data = params, headers = { "Content-type": "application/x-www-form-urlencoded" })
    if response.json()['code'] == 0:
        cookies = response.json()['data']['cookie_info']['cookies']
        cookie_text = ""
        for c in cookies:
            cookie_text += c['name'] + "=" + c['value'] + ";"
        s1 = re.findall(r'bili_jct=(\S+)', cookie_text, re.M)
        s2 = re.findall(r'DedeUserID=(\S+)', cookie_text, re.M)
        _session.update({
            "cookies": cookie_text,
            "csrf": s1[0].split(";")[0],
            "uid": s2[0].split(";")[0],
            "token": response.json()['data']['token_info']['access_token']
        })
    else:
        print("login failed: ", response.json()['message'])
    return response.json()['code']

def bilibili_get_recommand_video():
    video_list = []
    headers = APPAPI_HEADER.copy()
    headers['Cookie'] = _session['cookies']
    ts = str(int(time.mktime(datetime.datetime.now().timetuple())))
    params = "appkey=" + APP_KEY + "&build=5260003&screen=xxhdpi&mobi_app=android&platform=android&ts=" + ts
    response = requests.get("https://app.bilibili.com/x/show/old?" + params, headers = headers)
    for rd in response.json()['result']:
        if rd['type'] != 'live' and rd['type'] != 'activity' and rd['type'] != 'bangumi_2':
            for vi in rd['body']:
                video_list.append(int(vi['param']))
    return video_list

def bilibili_query_reward():
    headers = WEBAPI_HEADER.copy()
    headers['Referer'] = "https://account.bilibili.com/account/home"
    headers['Cookie'] = _session['cookies']
    del headers['Host']
    response = requests.get("https://account.bilibili.com/home/reward", headers = headers)
    rd = response.json()['data']
    return rd['watch_av'], rd['share_av'], int(rd['coins_av'])

def bilibili_donate_coin(aid):
    headers = WEBAPI_HEADER.copy()
    headers['Cookie'] = _session['cookies']
    headers['Referer'] = "https://www.bilibili.com/video/av" + str(aid)
    headers['Origin'] = "https://www.bilibili.com"
    data = { "aid": aid, "multiply": "1", "cross_domain": "true", "csrf": _session['csrf'] }
    response = requests.post("https://api.bilibili.com/x/web-interface/coin/add", data = data, headers = headers)
    print("donate coin av%d %s" % (aid, 'failed' if response.json()['code'] else 'succeed'))
    return response.json()['code']

def bilibili_share(aid):
    headers = APPAPI_HEADER.copy()
    headers['Cookie'] = _session['cookies']
    ts = str(int(time.mktime(datetime.datetime.now().timetuple())))
    params = "access_key=" + _session['token'] + "&aid=" + str(aid) + "&appkey=" + APP_KEY + "&build=5260003&from=7&mobi_app=android&platform=android&ts=" + ts
    data = {
        "access_key": _session['token'], "aid": aid,
        "appkey": APP_KEY, "build": "5260003", "from": "7", "mobi_app": "android", "platform": "android", "ts": ts, "sign": _calc_sign(params)
    }
    response = requests.post("https://app.bilibili.com/x/v2/view/share/add", headers = headers, data = data)
    print("share av%d %s" % (aid, 'failed' if response.json()['code'] else 'succeed'))
    return response.json()['code']

def bilibili_watch(aid):
    response = requests.get("https://www.bilibili.com/widget/getPageList?aid=" + str(aid))
    cid = response.json()[0]['cid']
    headers = WEBAPI_HEADER.copy()
    headers['Cookie'] = _session['cookies']
    headers['Referer'] = "https://www.bilibili.com/video/av" + str(aid)
    data = {
        "aid": aid, "cid": cid, "mid": _session['uid'], "csrf": _session['csrf'],
        "start_ts": str(int(time.time() * 1000)), "played_time": "0", "realtime": "0", "type": "3", "dt": "2", "play_type": "1"
    }
    response = requests.post("https://api.bilibili.com/x/report/web/heartbeat", headers = headers, data = data)
    print("watch av%d %s" % (aid, 'failed' if response.json()['code'] else 'succeed'))
    return response.json()['code']

# __main__
if bilibili_login("user", "password") == 0:
    video_list = bilibili_get_recommand_video()
    watch_av, share_av, coins_av = bilibili_query_reward()
    while coins_av < 50:
        aid = random.choice(video_list)
        if bilibili_donate_coin(aid) == 0:
            coins_av += 10
    if not watch_av:
        bilibili_watch(random.choice(video_list))
    if not share_av:
        bilibili_share(random.choice(video_list))
    print("done")
