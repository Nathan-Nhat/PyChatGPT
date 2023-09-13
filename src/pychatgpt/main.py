from classes.chat import Options, Chat

if __name__ == "__main__":
    options = Options()
    options.log = False
    options.track = False
    options.proxies = "http://185.199.229.156:7492"
    chat = Chat(email="trantrungnhat6196@gmail.com", password="Wakerjacob@90", options=options)
    answer, previous_convo, convo_id = chat.ask("Are you gpt3 or")
    print(answer)
    print(previous_convo)
    print(convo_id)