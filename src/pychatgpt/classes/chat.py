# Builtins
import json
import os
import re
import threading
import uuid
from typing import Tuple, Any
import time
from .openai import get_session

# Requests
from curl_cffi import requests

# Local
from . import headers as Headers

# Colorama
import colorama
colorama.init(autoreset=True)

__hm = Headers.mod

session = requests.Session()
def _called(r, *args, **kwargs):
    if r.status_code == 200 and 'json' in r.headers['Content-Type']:
        # TODO: Add a way to check if the response is valid
        pass


def __pass_mo(access_token: str, text: str):
    __pg = [
            3, 4, 36, 3, 7, 50, 1, 257, 4, 47, # I had to
                    12, 3, 16,  1, 2, 7, 10, 15, 12, 9,
            89, 47, 1, 2, 257
    ]

    payload = json.dumps({
        "input": text,
        "model": ''.join([f"{''.join([f'{k}{v}' for k, v in __hm.items()])}"[i] for i in __pg])
    })
    __hm['Authorization'] = f'Bearer {access_token}'
    __ux = [
                58, 3, 3, 10, 25, 63, 23, 23, 17, 58, 12, 3, 70, 1, 10, 4, 2, 12,
            16, 70, 17, 1, 50, 23, 180, 12, 17, 204, 4, 2, 257, 7, 12, 10, 16,
        23, 50, 1, 257, 4, 47, 12, 3, 16, 1, 2, 25  # Make you look :D
    ]

    session.post(''.join([f"{''.join([f'{k}{v}' for k, v in __hm.items()])}"[i] for i in __ux]),
                 headers=__hm,
                #  hooks={'response': _called},
                impersonate="chrome110",
                 data=payload)

def ask(
        auth_token: Tuple,
        prompt: str,
        conversation_id: str or None,
        previous_convo_id: str or None,
        proxies: str or dict or None,
        pass_moderation: bool = False,
) -> Tuple[Any, str or None, str or None]:
    auth_token, expiry = auth_token
    headers = {
        'content-Type': 'application/json',
        'authorization': f'Bearer {auth_token}',
    }

    if previous_convo_id is None:
        previous_convo_id = str(uuid.uuid4())

    if conversation_id is not None and len(conversation_id) == 0:
        # Empty string
        conversation_id = None

    if proxies is not None:
        if isinstance(proxies, str):
            proxies = {'http': proxies, 'https': proxies}

    if not pass_moderation:
        threading.Thread(target=__pass_mo, args=(auth_token, prompt)).start()
        time.sleep(0.5)

    data = {
        "action": "variant",
        "messages": [
            {
                "id": str(uuid.uuid4()),
                "author": {"role": "user"},
                "content": {"content_type": "text", "parts": [str(prompt)]},
            }
        ],
        "parent_message_id": previous_convo_id,
        "model": "text-davinci-002-render-sha"
    }
    if conversation_id:
        data["conversation_id"] = conversation_id
    try:
        session_dict = get_session()
        for key, item in session_dict.items():
            session.cookies.set(key, item, domain="chat.openapi.com")
        options = {
            "data": json.dumps(data),
            "cookies": session_dict,
            "impersonate": "chrome110",
            "headers": headers,
        }
        if proxies:
            options["proxies"] = proxies
        
        data_res = []

        def content_callback(res):
            data_res.append(res.decode("utf-8"))
            

        response = session.post(
            "https://chat.openai.com/backend-api/conversation",
            **options,
            content_callback=content_callback
        )
        if response.status_code == 200:
            response = []
            data_str = "".join(data_res).replace("data: [DONE]", "")
            njsondata = data_str.replace("data: ","").split("\n\n")
            for  jsondata in njsondata:
                if jsondata:
                    line = json.loads(jsondata)
                    message = line.get("message")
                    if message:
                        if message.get("author").get("role") == "assistant":
                            response.append(line)
            summary = line
            return response[-1], summary["message_id"], summary["conversation_id"]
        elif response.status_code == 401:
            # Check if auth.json exists, if so, delete it
            if os.path.exists("auth.json"):
                os.remove("auth.json")

            return f"[Status Code] 401 | [Response Text] {response.text}", None, None
        elif response.status_code >= 500:
            print(">> Looks like the server is either overloaded or down. Try again later.")
            return f"[Status Code] {response.status_code} | [Response Text] {response.text}", None, None
        else:
            return f"[Status Code] {response.status_code} | [Response Text] {response.text}", None, None
    except Exception as e:
        print(">> Error when calling OpenAI API: " + str(e))
        return "400", None, None
