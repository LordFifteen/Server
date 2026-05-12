import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from os import urandom

class SecureClient:
    def __init__(self, host='localhost', port=9090):
        self.host = host
        self.port = port
        self.socket = None
        self.derived_key = None

    def connect(self):
        print(f"Подключение к {self.host}:{self.port}...")
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))

        # 1. Получаем параметры DH от сервера
        dh_params_bytes = self.socket.recv(4096)
        dh_parameters = serialization.load_pem_parameters(
            dh_params_bytes, backend=default_backend()
        )
        print("[+] Параметры DH получены от сервера")

        # 2. Генерируем свои ключи на основе параметров сервера
        client_private = dh_parameters.generate_private_key()
        client_public = client_private.public_key()

        # 3. Получаем публичный ключ сервера
        server_public_bytes = self.socket.recv(4096)
        server_public = serialization.load_pem_public_key(
            server_public_bytes, backend=default_backend()
        )
        print("[+] Публичный ключ сервера получен")

        # 4. Отправляем свой публичный ключ
        self.socket.sendall(client_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        print("[+] Свой ключ отправлен серверу")

        # 5. Вычисляем общий ключ
        shared_secret = client_private.exchange(server_public)
        self.derived_key = HKDF(
            algorithm=hashes.SHA256(), length=32,
            salt=None, info=b'secure-chat', backend=default_backend()
        ).derive(shared_secret)

        print("[+] Защищённый канал установлен!\n")
        return True

    def send_message(self, message):
        if not self.socket or not self.derived_key:
            return None

        #Шифрование
        msg_bytes = message.encode('utf-8')
        iv = urandom(16)
        pad_len = 16 - (len(msg_bytes) % 16)
        padded = msg_bytes + bytes([pad_len] * pad_len)
        cipher = Cipher(algorithms.AES(self.derived_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        self.socket.sendall(iv + encryptor.update(padded) + encryptor.finalize())

        #Получение и расшифровка ответа
        encrypted_response = self.socket.recv(4096)
        if not encrypted_response:
            return None

        iv_r = encrypted_response[:16]
        ct_r = encrypted_response[16:]
        cipher = Cipher(algorithms.AES(self.derived_key), modes.CBC(iv_r), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_r = decryptor.update(ct_r) + decryptor.finalize()
        return padded_r[:-padded_r[-1]].decode('utf-8')

    def close(self):
        if self.socket:
            self.socket.close()

if __name__ == "__main__":
    client = SecureClient()
    try:
        client.connect()
        print("Защищённый чат. Введите 'exit' для выхода.\n")
        while True:
            msg = input("Вы: ")
            if msg.lower() == 'exit':
                client.send_message('exit')
                break
            response = client.send_message(msg)
            if response:
                print(f"Сервер: {response}")
            else:
                print("Сервер не ответил")
                break
    except ConnectionRefusedError:
        print("Ошибка: сервер не запущен!")
    except Exception as e:
        print(f"Ошибка: {e}")
    finally:
        client.close()
