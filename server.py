from tkinter import *
from tkinter import messagebox
import socket
from threading import Thread
import sqlite3
from datetime import datetime
import queue

hostname = ''
ip = socket.gethostbyname(hostname)
BLFSIZ = 1024
server_socket = None
accept_thread = None
recv_thread_list = []
clientlist = []
login = 'User'
password = 'Pass'
nsg_queue = queue.Queue()

# Функция проверки пароля
def checkDb(name, password):
    try:
        sqlite_connection = sqlite3.connect('chat.db')
        cursor = sqlite_connection.cursor()
        sqlite_select_query = """SELECT password FROM users WHERE user = (?)"""
        passwordDb = cursor.execute(sqlite_select_query, (name,)).fetchone()

        if passwordDb is None:
            sqlite_insert_query = """INSERT INTO users
                                    (user, password)
                                    VALUES (?,?);"""
            cursor.execute(sqlite_insert_query, (name, password,))
            sqlite_connection.commit()
            answer = True
        elif password == passwordDb[0]:
            answer = True
        else:
            answer = False

    except sqlite3.Error as error:
        print("Ошибка при работе с SQLite", error)
    except Exception as e:
        print(e)
    finally:
        if (sqlite_connection):
            cursor.close()
            sqlite_connection.close()
            return answer

# Функция сохранения сообщений пользователей
def SaveMessage(user, message):
    try:
        now = datetime.now()
        current_time = now.strftime("%d/%m/%y,%H:%M:%S")
        sqlite_connection = sqlite3.connect('chat.db')
        cursor = sqlite_connection.cursor()
        sqlite_insert_query = """INSERT INTO messages
                                (user, message, time)
                                VALUES (?,?,?);"""
        cursor.execute(sqlite_insert_query, (user, message, current_time))
        sqlite_connection.commit()
        cursor.close()
    except sqlite3.Error as error:
        print("Ошибка при работе с SQLite", error)
    finally:
        if (sqlite_connection):
            sqlite_connection.close()

listening = False  # Глобальная переменная для отслеживания состояния прослушивания

def Listen():
    global server_socket
    global accept_thread
    global sendButton
    global ListenButton
    global listening  # Используйте глобальную переменную

    try:
        if listening:
            StopListen()
            ListenButton.configure(text="Listen")  # Измените текст кнопки
        else:
            local_ip = '192.168.100.100'  # IP-адрес для локального соединения
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ADDR = (local_ip, int(host_port.get()))
            server_socket.bind(ADDR)
            server_socket.listen(5)
            accept_thread = Thread(target=AcceptConn)
            accept_thread.start()
            ListenButton.configure(text="Stop Listening")  # Измените текст кнопки
            sendButton.configure(state='normal')
            listening = True  # Установите флаг состояния прослушивания
    except OverflowError:
        print("Port number too large")
    except ValueError:
        print("Invalid Port number")

def StopListen():
    global server_socket
    global clientlist
    global listening  # Используйте глобальную переменную

    if server_socket:
        server_socket.close()
    
    if accept_thread and accept_thread.is_alive():
        accept_thread.join()

    for client in clientlist:
        client_socket, _ = client
        client_socket.close()

    # Проверяем, что потоки созданы и активны, прежде чем пытаться их остановить
    for thread in recv_thread_list:
        if thread and thread.is_alive():
            thread.join()
    
    clientlist = []
    listening = False  # Установите флаг состояния прослушивания

def AcceptConn():
    while True:
        try:
            if server_socket:
                client = so, (ip, port) = server_socket.accept()
                clientlist.append(client)
                receive_thread = Thread(target=RecvMessage, args=(so,))
                recv_thread_list.append(receive_thread)
                receive_thread.daemon = True
                receive_thread.start()
                
                # Отправка сообщения о успешном подключении клиенту
                connected_msg = "You are now connected to the server as " + uname.get()  # Изменилась эта строка
                SendServerMessage("Server: " + connected_msg)  # Отправить сообщение от сервера клиенту
        except OSError:
            print("Accept Error")
            break




def RecvMessage(client_socket):
    while True:
        try:
            message = client_socket.recv(BLFSIZ).decode("utf-8")
            if not message:
                break
            UpdateView(message)  # Изменено: вызов функции UpdateView для обновления интерфейса
        except ConnectionResetError:
            break
    client_socket.close()

def Broadcast(message, sender_socket):
    for client_socket, _ in clientlist:
        if client_socket != sender_socket:
            try:
                client_socket.send(message.encode("utf-8"))
            except ConnectionResetError:
                continue

def UpdateView(message):
    msg_list.insert(END, message)

def SendMessage(client_socket, message):
    try:
        client_socket.send(message.encode("utf-8"))
    except ConnectionResetError:
        pass

def SendServerMessage(message):
    for client_socket, _ in clientlist:
        try:
            client_socket.send(message.encode("utf-8"))
        except ConnectionResetError:
            continue
    # После отправки сообщения, обновите интерфейс сервера
    UpdateView(message)  # Добавьте эту строку

def SendServerMessageFromInput():
    message_text = message.get(1.0, END)  # Получаем текст из виджета сообщения
    SendServerMessage("Server: " + message_text)  # Отправляем сообщение от сервера
    message.delete(1.0, END)  # Очищаем виджет сообщения

def on_closing():
    StopListen()
    mainWindow.destroy()

conn = sqlite3.connect('chat.db')
cur = conn.cursor()
if not cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='messages';").fetchone():
    cur.execute("""
    CREATE TABLE messages (user TEXT REFERENCES users (user) ON DELETE CASCADE,
    messages TEXT NOT NULL, time DATETIME NOT NULL);
    """)

if not cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';").fetchone():
    cur.execute("""
    CREATE TABLE users (user TEXT UNIQUE, password TEXT NOT NULL);
    """)

conn.commit()
conn.close()

# Графический интерфейс
mainWindow = Tk()
mainWindow.title('Chat Application - Server')

configFrame = Frame(mainWindow)

Label(configFrame, text="My Hostname: ").grid(row=0, column=0)
Label(configFrame, text=hostname).grid(row=0, column=1)
Label(configFrame, text='Name').grid(row=0, column=2)
uname = Entry(configFrame, state="normal")
uname.grid(row=0, column=3)
uname.insert(END, "Host")

Label(configFrame, text="My IP: ").grid(row=1, column=0)
Label(configFrame, text=ip).grid(row=1, column=1)

Label(configFrame, text='Port').grid(row=2, column=0)
host_port = Entry(configFrame)
host_port.insert(END, '8008')
host_port.grid(row=2, column=1)

ListenButton = Button(configFrame, text='Listen', width=25, command=Listen)
ListenButton.grid(row=2, column=3)

configFrame.grid(row=0)

messagesFrame = Frame(mainWindow)
scrollbar = Scrollbar(messagesFrame)

msg_list = Listbox(messagesFrame, height=15, width=80, bg="silver", yscrollcommand=scrollbar.set)
msg_list.insert(0, '- - - - - - Beginning of Chat - - - - - -')
scrollbar.pack(side=RIGHT, fill=Y)
msg_list.pack(side=LEFT, fill=BOTH)
msg_list.pack()
messagesFrame.grid(row=4)

SendFrame = Frame(mainWindow)
message = Text(SendFrame, height=4)
message.grid(row=6, column=1)
SendFrame.grid(row=5)

sendButton = Button(SendFrame, text='Send', width=10, command=SendServerMessageFromInput)
sendButton.grid(row=6, column=2)
sendButton.configure(state='disabled')

mainWindow.protocol("WM_DELETE_WINDOW", on_closing)
mainWindow.mainloop()

