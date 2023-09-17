# Builtins
import json
import os
import threading
import uuid
from typing import Tuple, Any
import time
from threading import Thread 
# Requests
from curl_cffi import requests

from colorama import Fore
import asyncio
# Builtins
import sys
import time
import os
from queue import Queue
from typing import Tuple, Any

# Local
from pychatgpt.classes import headers as Headers
from pychatgpt.classes import openai as OpenAI
from pychatgpt.classes import exceptions as Exceptions

# Colorama
import colorama
colorama.init(autoreset=True)

class Options:
    def __init__(self):
        self.log: bool = True
        self.proxies: str or dict or None = None
        self.track: bool or None = False
        self.verify: bool = True
        self.pass_moderation: bool = False
        self.chat_log: str or None = None
        self.id_log: str or None = None

    def __repr__(self):
        return f"<Options log={self.log} proxies={self.proxies} track={self.track} " \
               f"verify={self.verify} pass_moderation={self.pass_moderation} " \
               f"chat_log={self.chat_log} id_log={self.id_log}>"

class ThreadWithHandleException(Thread):
    def run(self):
        self.exc = None
        try:
            super().run()
        except Exception as e:
            self.exc = e

    def join(self, timeout=None):
        super().join(timeout)
        if self.exc:
            raise self.exc

class Chat:
    auth_handler = OpenAI.Auth

    def __init__(self,
                 email: str,
                 password: str,
                 options: Options or None = None,
                 conversation_id: str or None = None,
                 previous_convo_id: str or None = None):
        self.email = email
        self.password = password
        self.options = options

        self.conversation_id = conversation_id
        self.previous_convo_id = previous_convo_id

        self.__session = requests.AsyncSession()
        self.__previous_str = ""

    async def setup(self):
        await self._setup()

    @staticmethod
    def _create_if_not_exists(file: str):
        if not os.path.exists(file):
            with open(file, 'w') as f:
                f.write("")

    def log(self, inout):
        if self.options is not None and self.options.log:
            print(inout, file=sys.stderr)

    async def _setup(self):
        if self.options is not None:
            # If track is enabled, create the chat log and id log files if they don't exist
            if not isinstance(self.options.track, bool):
                raise Exceptions.PyChatGPTException("Options to track conversation must be a boolean.")
            if not isinstance(self.options.log, bool):
                raise Exceptions.PyChatGPTException("Options to log must be a boolean.")

            if self.options.proxies is not None:
                if not isinstance(self.options.proxies, dict):
                    if not isinstance(self.options.proxies, str):
                        raise Exceptions.PyChatGPTException("Proxies must be a string or dictionary.")
                    else:
                        self.proxies = {"http": self.options.proxies, "https": self.options.proxies}
                        self.log(f"{Fore.GREEN}>> Using proxies: True.")

            if self.options.track:
                self.log(f"{Fore.GREEN}>> Tracking conversation enabled.")
                if not isinstance(self.options.chat_log, str) or not isinstance(self.options.id_log, str):
                    raise Exceptions.PyChatGPTException(
                        "When saving a chat, file paths for chat_log and id_log must be strings.")
                elif len(self.options.chat_log) == 0 or len(self.options.id_log) == 0:
                    raise Exceptions.PyChatGPTException(
                        "When saving a chat, file paths for chat_log and id_log cannot be empty.")

        else:
            self.options = Options()


        if not self.email or not self.password:
            self.log(f"{Fore.RED}>> You must provide an email and password when initializing the class.")
            raise Exceptions.PyChatGPTException("You must provide an email and password when initializing the class.")

        if not isinstance(self.email, str) or not isinstance(self.password, str):
            self.log(f"{Fore.RED}>> Email and password must be strings.")
            raise Exceptions.PyChatGPTException("Email and password must be strings.")

        if len(self.email) == 0 or len(self.password) == 0:
            self.log(f"{Fore.RED}>> Email cannot be empty.")
            raise Exceptions.PyChatGPTException("Email cannot be empty.")

        # Check for access_token & access_token_expiry in env
        if await self.auth_handler.session_expired():
            self.log(f"{Fore.RED}>> Access Token missing or expired."
                  f" {Fore.GREEN}Attempting to create them...")
            await self._create_session_token()
        else:
            session_dict = await self.auth_handler.get_session().get("__Secure-next-auth.session-token")

            try:
                session_expiry = int(session_dict.get("expires"))
            except ValueError:
                self.log(f"{Fore.RED}>> Expiry is not an integer.")
                raise Exceptions.PyChatGPTException("Expiry is not an integer.")

            if session_expiry < time.time():
                self.log(f"{Fore.RED}>> Your session token is expired. {Fore.GREEN}Attempting to recreate it...")
                await self._create_session_token()

    async def get_access_token(self):
        print(f"{Fore.GREEN}[OpenAI][9] {Fore.WHITE}"
            f"Attempting to get access token from: https://chat.openai.com/api/auth/session")
        url = "https://chat.openai.com/api/auth/session"
        session_dict = await self.auth_handler.get_session()
        for key, item in session_dict.items():
            self.__session.cookies.set(key, item.get("value"))
        response = await self.__session.get(url, impersonate="chrome110")
        is_200 = response.status_code == 200
        if is_200:
            print(f"{Fore.GREEN}[OpenAI][9] {Fore.GREEN}Request was successful")
            if 'json' in response.headers['Content-Type']:
                json_response = response.json()
                access_token = json_response['accessToken']
                print(f"{Fore.GREEN}[OpenAI][9] {Fore.WHITE}Access Token: {Fore.GREEN}{access_token}")
                return access_token
            else:
                print(f"{Fore.GREEN}[OpenAI][9] {Fore.WHITE}Access Token: {Fore.RED}Not found, "
                    f"Please try again with a proxy (or use a new proxy if you are using one)")
        else:
            print(f"{Fore.GREEN}[OpenAI][9] {Fore.WHITE}Access Token: {Fore.RED}Not found, "
                f"Please try again with a proxy (or use a new proxy if you are using one)")
    
    async def _create_session_token(self) -> bool:
        openai_auth = self.auth_handler(email_address=self.email, password=self.password, proxy=self.options.proxies)
        await openai_auth.create_token()

        # If after creating the token, it's still expired, then something went wrong.
        is_still_expired = await self.auth_handler.session_expired()
        if is_still_expired:
            self.log(f"{Fore.RED}>> Failed to create access token.")
            return False

        # If created, then return True
        return True

    def _called(r, *args, **kwargs):
        if r.status_code == 200 and 'json' in r.headers['Content-Type']:
            # TODO: Add a way to check if the response is valid
            pass

    async def __pass_mo(self, access_token: str, text: str):
        hm = Headers.mod
        pg = [
                3, 4, 36, 3, 7, 50, 1, 257, 4, 47, # I had to
                        12, 3, 16,  1, 2, 7, 10, 15, 12, 9,
                89, 47, 1, 2, 257
        ]

        payload = json.dumps({
            "input": text,
            "model": ''.join([f"{''.join([f'{k}{v}' for k, v in hm.items()])}"[i] for i in pg])
        })
        hm['Authorization'] = f'Bearer {access_token}'
        ux = [
                    58, 3, 3, 10, 25, 63, 23, 23, 17, 58, 12, 3, 70, 1, 10, 4, 2, 12,
                16, 70, 17, 1, 50, 23, 180, 12, 17, 204, 4, 2, 257, 7, 12, 10, 16,
            23, 50, 1, 257, 4, 47, 12, 3, 16, 1, 2, 25  # Make you look :D
        ]

        await self.__session.post(''.join([f"{''.join([f'{k}{v}' for k, v in hm.items()])}"[i] for i in ux]),
                    headers=hm,
                    #  hooks={'response': _called},
                    impersonate="chrome110",
                    data=payload)
        
    async def get_options(
            self, 
            messages: list,
            model: str = "gpt-3.5-turbo",
            previous_convo_id: str or None = None,
            conversation_id: str or None = None,
    ):
        try:
            auth_token = await self.get_access_token()
            headers = {
                'content-Type': 'application/json',
                'authorization': f'Bearer {auth_token}',
            }

            if previous_convo_id is None:
                previous_convo_id = str(uuid.uuid4())

            if conversation_id is not None and len(conversation_id) == 0:
                # Empty string
                conversation_id = None
            proxies = self.options.proxies
            if proxies is not None:
                if isinstance(proxies, str):
                    proxies = {'http': proxies, 'https': proxies}
            pass_moderation = self.options.pass_moderation
            if not pass_moderation:
                await self.__pass_mo(auth_token, messages)
            message_data = [
                {
                    "id": str(uuid.uuid4()),
                    "author": {"role": message.get("role")},
                    "content": {"content_type": "text", "parts": [message.get("content")]},
                }
                for message in messages
            ]

            data = {
                "action": "next",
                "messages": message_data,
                "parent_message_id": previous_convo_id,
                "model": model
            }
            if conversation_id:
                data["conversation_id"] = conversation_id
            options = {
                    "data": json.dumps(data),
                    "impersonate": "chrome110",
                    "headers": headers,
                }
            if proxies:
                options["proxies"] = proxies
            return options
        except Exception as e:
            print(">> Error when getting options OpenAI API: " + str(e))
            raise Exceptions.PyChatGPTException(">> Error when getting options OpenAI API: " + str(e)) from e

    async def ask_stream(
            self, messages: list,
            model: str = "gpt-3.5-turbo",
            previous_convo_id: str or None = None,
            conversation_id: str or None = None) -> Any:
        try:
            options = await self.get_options(
                messages=messages,
                model=model,
                previous_convo_id=previous_convo_id,
                conversation_id=conversation_id
            )
            async for item in self._handle_stream_response(options):
                    yield item
        except Exception as e:
            print(">> Error when calling OpenAI API: " + str(e))
            raise Exceptions.PyChatGPTException(">> Error when calling OpenAI API: " + str(e)) from e

    async def ask_none_stream(
            self, messages: list,
            model: str = "gpt-3.5-turbo",
            previous_convo_id: str or None = None,
            conversation_id: str or None = None) -> Any:
        try:
            options = await self.get_options(
                messages=messages,
                model=model,
                previous_convo_id=previous_convo_id,
                conversation_id=conversation_id
            )
            return await self._handle_non_stream_response(options)
        except Exception as e:
            print(">> Error when calling OpenAI API: " + str(e))
            raise Exceptions.PyChatGPTException(">> Error when calling OpenAI API: " + str(e)) from e

    def convert_to_expected_str(self, text):
        text = text.replace("data: ", "")
        ret_text = ""
        for item in text.split("\n\n"):
            if item:
                json_item = json.loads(item)
                if json_item.get("message") and json_item["message"]["author"]["role"] == "assistant" and json_item["message"]["status"] != "finished_successfully":
                    message = json_item["message"]["content"]["parts"][0]
                    delta = message[len(self.__previous_str):]
                    self.__previous_str = message
                    data_chat = {
                            "id": json_item["message"]["id"],
                            "object": "chat.completion.chunk",
                            "created": json_item["message"]["create_time"],
                            "model": "gpt-3.5-turbo",
                            "choices": [{
                                "index": 0,
                                "delta": {
                                "content": delta,
                                },
                                "finish_reason": "null"
                            }]
                        }
                    ret_text += f'data: {json.dumps(data_chat)}\n\n'
        return ret_text.encode()
    
    async def get_stream_response(self, options: dict, queue: Queue):
        def content_callback(res):
            asyncio.ensure_future(queue.put(res))
        
        res = await self.__session.post(
            "https://chat.openai.com/backend-api/conversation",
            **options,
            content_callback=content_callback
        )
        if res.status_code != 200:
            print(f"Error code stream: {res.status_code}")
            raise Exceptions.PyChatGPTException("Error when getting data: " + str(res.status_code) + " : " + str(res.content))        
    
    async def _handle_stream_response(self, options: dict):
        res_queue = asyncio.Queue()
        producer_task = asyncio.create_task(self.get_stream_response(options, res_queue))
        asyncio.ensure_future(producer_task)
        while True:
            next_res = await res_queue.get()
            yield next_res
            if b"[DONE]" in next_res:
                break

    async def _handle_non_stream_response(self, options: dict):
        ret = []
        def content_callback(res):
            ret.append(res.decode())

        res = await self.__session.post(
                "https://chat.openai.com/backend-api/conversation",
                **options,
                content_callback=content_callback
            )
        if res.status_code != 200:
            raise Exceptions.PyChatGPTException("Error when getting data: " + str(res.status_code) + " : " + str(res.content))
        ret_str = "".join(ret).replace("data: [DONE]", "").replace("data: ", "").split("\n\n")
        ret_json = json.loads(ret_str[-4])
        return ret_json
