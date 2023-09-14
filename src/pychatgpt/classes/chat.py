# Builtins
import json
import os
import threading
import uuid
from typing import Tuple, Any
import time

# Requests
from curl_cffi import requests

from colorama import Fore

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

        self.__chat_history: list or None = None
        self.__session = requests.Session()

        self._setup()

    @staticmethod
    def _create_if_not_exists(file: str):
        if not os.path.exists(file):
            with open(file, 'w') as f:
                f.write("")

    def log(self, inout):
        if self.options is not None and self.options.log:
            print(inout, file=sys.stderr)

    def _setup(self):
        if self.options is not None:
            # If track is enabled, create the chat log and id log files if they don't exist
            if not isinstance(self.options.track, bool):
                raise Exceptions.PyChatGPTException("Options to track conversation must be a boolean.")
            if not isinstance(self.options.log, bool):
                raise Exceptions.PyChatGPTException("Options to log must be a boolean.")

            if self.options.track:
                if self.options.chat_log is not None:
                    self._create_if_not_exists(os.path.abspath(self.options.chat_log))
                    self.options.chat_log = os.path.abspath(self.options.chat_log)
                else:
                    # Create a chat log file called chat_log.txt
                    self.options.chat_log = "chat_log.txt"
                    self._create_if_not_exists(self.options.chat_log)

                if self.options.id_log is not None:
                    self._create_if_not_exists(os.path.abspath(self.options.id_log))
                    self.options.id_log = os.path.abspath(self.options.id_log)
                else:
                    # Create a chat log file called id_log.txt
                    self.options.id_log = "id_log.txt"
                    self._create_if_not_exists(self.options.id_log)

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

                self.__chat_history = []
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

        if self.options is not None and self.options.track:
            try:
                with open(self.options.id_log, "r") as f:
                    # Check if there's any data in the file
                    if os.path.getsize(self.options.id_log) > 0:
                        self.previous_convo_id = f.readline().strip()
                        self.conversation_id = f.readline().strip()
                    else:
                        self.conversation_id = None
            except IOError:
                raise Exceptions.PyChatGPTException("When resuming a chat, conversation id and previous conversation id in id_log must be separated by newlines.")
            except Exception:
                raise Exceptions.PyChatGPTException("When resuming a chat, there was an issue reading id_log, make sure that it is formatted correctly.")

        # Check for access_token & access_token_expiry in env
        if self.auth_handler.session_expired():
            self.log(f"{Fore.RED}>> Access Token missing or expired."
                  f" {Fore.GREEN}Attempting to create them...")
            self._create_session_token()
        else:
            session_dict = self.auth_handler.get_session().get("__Secure-next-auth.session-token")

            try:
                session_expiry = int(session_dict.get("expires"))
            except ValueError:
                self.log(f"{Fore.RED}>> Expiry is not an integer.")
                raise Exceptions.PyChatGPTException("Expiry is not an integer.")

            if session_expiry < time.time():
                self.log(f"{Fore.RED}>> Your session token is expired. {Fore.GREEN}Attempting to recreate it...")
                self._create_session_token()

    def get_access_token(self):
        print(f"{Fore.GREEN}[OpenAI][9] {Fore.WHITE}"
            f"Attempting to get access token from: https://chat.openai.com/api/auth/session")
        url = "https://chat.openai.com/api/auth/session"
        session_dict = self.auth_handler.get_session()
        for key, item in session_dict.items():
            self.__session.cookies.set(key, item.get("value"))
        response = self.__session.get(url, impersonate="chrome110")
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
    
    def _create_session_token(self) -> bool:
        openai_auth = self.auth_handler(email_address=self.email, password=self.password, proxy=self.options.proxies)
        openai_auth.create_token()

        # If after creating the token, it's still expired, then something went wrong.
        is_still_expired = self.auth_handler.session_expired()
        if is_still_expired:
            self.log(f"{Fore.RED}>> Failed to create access token.")
            return False

        # If created, then return True
        return True

    def ask(self, prompt: str,
            previous_convo_id: str or None = None,
            conversation_id: str or None = None,
            rep_queue: Queue or None = None
            ) -> Tuple[Any, None or str, None or str]:

        if prompt is None:
            self.log(f"{Fore.RED}>> Enter a prompt.")
            raise Exceptions.PyChatGPTException("Enter a prompt.")

        if not isinstance(prompt, str):
            raise Exceptions.PyChatGPTException("Prompt must be a string.")

        if len(prompt) == 0:
            raise Exceptions.PyChatGPTException("Prompt cannot be empty.")

        if rep_queue is not None and not isinstance(rep_queue, Queue):
            raise Exceptions.PyChatGPTException("Cannot enter a non-queue object as the response queue for threads.")

        # Check if the access token is expired
        if self.auth_handler.session_expired():
            self.log(f"{Fore.RED}>> Your session token is expired. {Fore.GREEN}Attempting to recreate it...")
            did_create = self._create_session_token()
            if did_create:
                self.log(f"{Fore.GREEN}>> Successfully recreated session token.")
            else:
                self.log(f"{Fore.RED}>> Failed to recreate session token.")
                raise Exceptions.PyChatGPTException("Failed to recreate session token.")

        # Set conversation IDs if supplied
        if previous_convo_id is not None:
            self.previous_convo_id = previous_convo_id
        if conversation_id is not None:
            self.conversation_id = conversation_id

        answer,  previous_convo, convo_id = self._ask(prompt=prompt,
                                                           conversation_id=self.conversation_id,
                                                           previous_convo_id=self.previous_convo_id,
                                                           proxies=self.options.proxies,
                                                           pass_moderation=self.options.pass_moderation)

        if rep_queue is not None:
            rep_queue.put((prompt, answer))

        if answer == "400" or answer == "401":
            self.log(f"{Fore.RED}>> Failed to get a response from the API.")
            return None
        
        self.conversation_id = convo_id
        self.previous_convo_id = previous_convo

        if self.options.track:
            self.__chat_history.append("You: " + prompt)
            self.__chat_history.append("Chat GPT: " + answer)
            self.save_data()

        return answer, previous_convo, convo_id

    def save_data(self):
        if self.options.track:
            try:
                with open(self.options.chat_log, "a") as f:
                    f.write("\n".join(self.__chat_history) + "\n")

                with open(self.options.id_log, "w") as f:
                    if self.previous_convo_id:
                        f.write(str(self.previous_convo_id) + "\n")
                    if self.conversation_id:
                        f.write(str(self.conversation_id) + "\n")

            except Exception as ex:
                self.log(f"{Fore.RED}>> Failed to save chat and ids to chat log and id_log."
                      f"{ex}")
            finally:
                self.__chat_history = []

    def _called(r, *args, **kwargs):
        if r.status_code == 200 and 'json' in r.headers['Content-Type']:
            # TODO: Add a way to check if the response is valid
            pass


    def __pass_mo(self, access_token: str, text: str):
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

        self.__session.post(''.join([f"{''.join([f'{k}{v}' for k, v in hm.items()])}"[i] for i in ux]),
                    headers=hm,
                    #  hooks={'response': _called},
                    impersonate="chrome110",
                    data=payload)

    def _ask(
            self,
            prompt: str,
            conversation_id: str or None,
            previous_convo_id: str or None,
            proxies: str or dict or None,
            pass_moderation: bool = False,
    ) -> Tuple[Any, str or None, str or None]:
        auth_token = self.get_access_token()
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
            threading.Thread(target=self.__pass_mo, args=(auth_token, prompt)).start()
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
            options = {
                "data": json.dumps(data),
                "impersonate": "chrome110",
                "headers": headers,
            }
            if proxies:
                options["proxies"] = proxies
            
            data_res = []

            def content_callback(res):
                data_res.append(res.decode("utf-8"))
                

            response = self.__session.post(
                "https://chat.openai.com/backend-api/conversation",
                **options,
                content_callback=content_callback
            )
            if response.status_code == 200:
                response = []
                data_str = "".join(data_res).replace("data: [DONE]", "")
                self.log(f"{Fore.GREEN}{data_str}")
                njsondata = data_str.replace("data: ","").split("\n\n")
                response = json.loads(njsondata[-2])
                return response, response["message"]["id"], response["conversation_id"]
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
