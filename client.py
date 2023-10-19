from tkinter import *
from tkinter import messagebox
import socket
from threading import Thread

hostname = socket.gethostname()
ip = socket.gethostbyname(hostname)
BUFSIZ = 1024
client_socket = None
receive_thread = None
message = None  # Добавим инициализацию объекта message

def Disconnect():
    global client_socket
    if client_socket:
        client_socket.close()
        client_socket = None  # Обнуляем сокет
    ConnectButton.configure(text="Connect", command=Connect)
    sendButton.configure(state="disabled")
    uname.configure(state="normal")
    upass.configure(state="normal")

def Connect():
    global client_socket
    global receive_thread

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Инициализация сокета

    try:
        client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ADDR = ('192.168.100.100', int(remote_port.get()))  # Используйте локальный IP-адрес
        print("Server Address: ", ADDR)

        client_socket.connect(ADDR)
        receive_thread = Thread(target=RecvMessage)
        receive_thread.start()
        SendLogin()

        ConnectButton.configure(text="Disconnect", command=Disconnect)
        sendButton.configure(state="normal")
        uname.configure(state="disabled")
        upass.configure(state="disabled")
    except OSError as ex:
        print("Connection to server failed")
    except ValueError:
        print("Port should be a valid number")

def RecvMessage():
    while True:
        try:
            msg = client_socket.recv(BUFSIZ).decode("utf-8")
            if msg == 'Incorrect login/password':
                msg_list.insert(END, 'Incorrect login or password, or user with that username already exists')
                Disconnect()
                break
            else:
                msg_list.insert(END, msg)
        except OSError as e:
            print(e)
            print("You have been disconnected from the server")
            Disconnect()
            break

def SendMessage():
    msg = message.get("1.0", END)
    message.delete("1.0", END)

    if client_socket is not None:
        try:
            client_socket.send(bytes(uname.get() + ": " + msg, "utf-8"))
            msg_list.insert(END, uname.get() + ": " + msg)  # Добавить сообщение в локальный список
        except Exception as e:
            msg_list.insert(END, "Error sending message: " + str(e))
            print("Error sending message:", str(e))
    else:
        msg_list.insert(END, "Error: Client socket is not initialized.")
        print("Error: Client socket is not initialized.")


def SendLogin():
    login_msg = "^7*@" + uname.get() + "@" + upass.get()
    client_socket.send(bytes(login_msg, "utf-8"))

def on_closing():
    if messagebox.askokcancel("Quit", "Do you want to quit?"):
        if client_socket:
            client_socket.close()
            if receive_thread and receive_thread is not None and receive_thread.is_alive():
                receive_thread.join()
            mainWindow.destroy()

mainWindow = Tk()
mainWindow.title('Chat Application - Client')

# Фрейм для настроек
configFrame = Frame(mainWindow)
configFrame.grid(row=0, column=0, padx=5, pady=5, sticky="w")

Label(configFrame, text='IP Address').grid(row=0, column=0, sticky="w")
remote_ip = Entry(configFrame)
remote_ip.insert(END, '')
remote_ip.grid(row=0, column=1, sticky="w")

Label(configFrame, text='Name').grid(row=0, column=2, sticky="w")
uname = Entry(configFrame, state='normal')
uname.insert(END, "User")
uname.grid(row=0, column=3, sticky="w")

Label(configFrame, text='Password').grid(row=1, column=0, sticky="w")
upass = Entry(configFrame, state='normal')
upass.insert(END, 'Pass')
upass.grid(row=1, column=1, sticky="w")

Label(configFrame, text='Port').grid(row=1, column=2, sticky="w")
remote_port = Entry(configFrame)
remote_port.insert(END, "8008")
remote_port.grid(row=1, column=3, sticky="w")

ConnectButton = Button(configFrame, text='Connect', width=25, command=Connect)
ConnectButton.grid(row=2, column=2, columnspan=2, sticky="w")

# Фрейм для сообщений
messagesFrame = Frame(mainWindow)
messagesFrame.grid(row=1, column=0, sticky="n")

scrollbar = Scrollbar(messagesFrame)

msg_list = Listbox(messagesFrame, height=15, width=80, bg="silver", yscrollcommand=scrollbar.set)
msg_list.insert(0, '- - - - - - Beginning of Chat - - - - - -')
scrollbar.pack(side=RIGHT, fill=Y)
msg_list.pack(side=LEFT, fill=BOTH)

# Создаем виджет для ввода сообщений
message = Text(mainWindow, height=4)
message.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky="ew")

# Создаем кнопку для отправки сообщения
sendButton = Button(mainWindow, text="Send", command=SendMessage)
sendButton.grid(row=2, column=2, padx=5, pady=5, sticky="e")

mainWindow.protocol("WM_DELETE_WINDOW", on_closing)
mainWindow.mainloop()
