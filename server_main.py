import os
import socket
import threading
import platform
import hashlib
import base64
from cryptography.fernet import Fernet

def clear_console():
    if platform.system() == "Windows":
        os.system("cls")
    else:
        os.system("clear")

def generate_fernet_key_from_password(password: str) -> bytes:
    """
    Из «пароля» получаем 32 байта (SHA256),
    потом кодируем в base64, чтобы получить ключ для Fernet.
    """
    sha = hashlib.sha256(password.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(sha)

def encrypt_message(fernet: Fernet, msg: str) -> bytes:
    return fernet.encrypt(msg.encode("utf-8"))

def decrypt_message(fernet: Fernet, enc: bytes) -> str:
    return fernet.decrypt(enc).decode("utf-8")

class Server:
    def __init__(self, host, port, password):
        self.host = host
        self.port = port
        self.fernet = Fernet(generate_fernet_key_from_password(password))

        self.server_socket = None
        self.running = False

        # Храним клиентов и их ники:
        #  clients_info[socket] = "Nickname"
        self.clients_info = {}
        # Для удобства также сделаем список/словарь, но он фактически дублирует ключи
        # (вся работа идёт по сокету).

    def start(self):
        """Запуск сервера."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen()
            self.running = True
        except Exception as e:
            print(f"Не удалось запустить сервер: {e}")
            return False

        local_ip = self.get_local_ip()
        print(f"Сервер запущен на {local_ip}:{self.port}.")
        print("Ожидание подключений...\n")

        threading.Thread(target=self.accept_clients, daemon=True).start()

        # Основной поток — ввод команд с консоли (сервер может отправлять MSG как "Server")
        self.handle_own_messages()
        return True

    def get_local_ip(self):
        """Определяем локальный IP (через Google DNS)."""
        temp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            temp_sock.connect(("8.8.8.8", 80))
            local_ip = temp_sock.getsockname()[0]
        except:
            local_ip = "127.0.0.1"
        finally:
            temp_sock.close()
        return local_ip

    def accept_clients(self):
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                print(f"Подключился клиент: {addr}")
                threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, addr),
                    daemon=True
                ).start()
            except OSError:
                break

    def handle_client(self, client_socket, addr):
        """
        Обрабатываем первоначальный протокол:
        1) Ждём "REG <nickname>" (зашифрованное).
        2) Если пришло — отправляем USERLIST + рассылаем JOIN.
        3) Далее на любой MSG <text> -> рассылаем MSG <nickname> <text>.
        """
        try:
            # Первое сообщение должно быть REG
            data = client_socket.recv(4096)
            if not data:
                print(f"Клиент {addr} отключился (пустое первое сообщение).")
                client_socket.close()
                return

            # Расшифруем
            raw_text = decrypt_message(self.fernet, data)
            # Ожидаем формат: "REG <nickname>"
            if not raw_text.startswith("REG "):
                print(f"Клиент {addr} не прислал REG, отключаем.")
                client_socket.close()
                return

            nickname = raw_text[4:].strip()
            if not nickname:
                nickname = "Anon"

            # Регистрируем в словаре
            self.clients_info[client_socket] = nickname
            print(f"[{addr}] => nickname='{nickname}'")

            # Отправляем этому клиенту "USERLIST <nick1> <nick2> ..."
            self.send_userlist(client_socket)

            # Рассылаем всем "JOIN <nickname>"
            self.broadcast_command(f"JOIN {nickname}")

            # Переходим к циклу чтения сообщений (MSG ...)
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break

                raw_text = decrypt_message(self.fernet, data)
                if raw_text.startswith("MSG "):
                    # Это сообщение в чат
                    text = raw_text[4:].strip()
                    # Рассылаем: "MSG <nickname> <text>"
                    cmd = f"MSG {nickname} {text}"
                    self.broadcast_command(cmd)
                else:
                    # Неизвестная команда
                    print(f"[{addr}] Неизвестное сообщение: {raw_text}")
                    # можно игнорировать или разорвать соединение
                    # break
        except Exception as e:
            print(f"Ошибка в handle_client {addr}: {e}")
        finally:
            # Клиент ушёл
            if client_socket in self.clients_info:
                nick_left = self.clients_info[client_socket]
                del self.clients_info[client_socket]
                print(f"Клиент {nick_left} ({addr}) отключился.")

                # Рассылаем "LEFT <nickname>"
                self.broadcast_command(f"LEFT {nick_left}")
            client_socket.close()

    def broadcast_command(self, command: str):
        """Рассылает строку `command` всем клиентам, зашифрованную."""
        enc = encrypt_message(self.fernet, command)
        remove_list = []
        for sock in self.clients_info:
            try:
                sock.sendall(enc)
            except:
                remove_list.append(sock)
        # Удаляем отвалившихся
        for sock in remove_list:
            if sock in self.clients_info:
                del self.clients_info[sock]
            sock.close()

    def send_userlist(self, client_socket):
        """
        Отправляем USERLIST <nick1> <nick2> ...
        """
        nicks = list(self.clients_info.values())
        cmd = "USERLIST " + " ".join(nicks)
        enc = encrypt_message(self.fernet, cmd)
        try:
            client_socket.sendall(enc)
        except:
            pass

    def handle_own_messages(self):
        """
        Сервер может отправлять сообщения, как будто это отдельный пользователь "Server".
        Если ввести /exit или /quit, остановим сервер.
        """
        while self.running:
            msg = input()
            if msg.lower() in ["/exit", "/quit"]:
                print("Останавливаем сервер...")
                self.shutdown()
                break
            # рассылаем MSG Server <msg>
            cmd = f"MSG Server {msg}"
            self.broadcast_command(cmd)

    def shutdown(self):
        self.running = False
        # Закрываем всех
        for c in list(self.clients_info.keys()):
            c.close()
        self.clients_info.clear()
        if self.server_socket:
            self.server_socket.close()
            self.server_socket = None

def main():
    clear_console()
    print("=== Triple Confirmation Server ===\n")

    host = "0.0.0.0"
    port_str = input("Введите порт (по умолчанию 9090): ").strip()
    if not port_str:
        port = 9090
    else:
        port = int(port_str)

    password = input("Введите пароль (ключ шифрования): ").strip()
    if not password:
        print("Пароль пустой — выходим.")
        return

    server = Server(host, port, password)
    success = server.start()
    if success:
        print("Сервер завершил работу.")


if __name__ == "__main__":
    main()
