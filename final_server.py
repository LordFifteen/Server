import socket
import threading
import logging
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from os import urandom

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[
        logging.FileHandler('server.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)


class SecureServer:
    def __init__(self, host='localhost', tcp_port=9090, udp_port=9091):
        self.host = host
        self.tcp_port = tcp_port
        self.udp_port = udp_port
        self.running = True
        #ЕДИНЫЕ параметры DH для всех
        print("Генерация параметров Диффи-Хеллмана...")
        self.dh_parameters = dh.generate_parameters(
            generator=2, key_size=2048, backend=default_backend()
        )
        #Сериализуем параметры для отправки клиентам
        self.dh_parameters_bytes = self.dh_parameters.parameter_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.ParameterFormat.PKCS3
        )
        print("Параметры DH сгенерированы!")

    def handle_tcp_client(self, client_socket, address):
        try:
            print(f"\n[+] Новый клиент: {address}")

            # 1. Отправляем параметры DH клиенту
            client_socket.sendall(self.dh_parameters_bytes)

            # 2. Генерируем ключи сервера для этого клиента
            server_private = self.dh_parameters.generate_private_key()
            server_public = server_private.public_key()

            # 3. Отправляем свой публичный ключ
            client_socket.sendall(server_public.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

            # 4. Получаем публичный ключ клиента
            client_public_bytes = client_socket.recv(4096)
            client_public = serialization.load_pem_public_key(
                client_public_bytes, backend=default_backend()
            )

            # 5. Вычисляем общий ключ
            shared_secret = server_private.exchange(client_public)
            derived_key = HKDF(
                algorithm=hashes.SHA256(), length=32,
                salt=None, info=b'secure-chat', backend=default_backend()
            ).derive(shared_secret)
            print(f"[+] Защищённый канал с {address} установлен")

            while self.running:
                encrypted_data = client_socket.recv(4096)
                if not encrypted_data:
                    break

                iv = encrypted_data[:16]
                ciphertext = encrypted_data[16:]
                cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                padded = decryptor.update(ciphertext) + decryptor.finalize()
                message = padded[:-padded[-1]].decode('utf-8')

                print(f"[{address}] {message}")
                logging.info(f"Сообщение от {address}: {message}")

                if message.lower() == 'exit':
                    break

                # Шифруем ответ
                response = f"Сервер получил: {message}".encode('utf-8')
                iv = urandom(16)
                pad_len = 16 - (len(response) % 16)
                padded = response + bytes([pad_len] * pad_len)
                cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                client_socket.sendall(iv + encryptor.update(padded) + encryptor.finalize())

        except Exception as e:
            print(f"[!] Ошибка с {address}: {e}")
        finally:
            client_socket.close()
            print(f"[-] Клиент {address} отключён")

    def start_tcp_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.tcp_port))
        server_socket.listen(5)
        server_socket.settimeout(1.0)
        print(f"\n[TCP] Сервер запущен на {self.host}:{self.tcp_port}")

        while self.running:
            try:
                client_sock, addr = server_socket.accept()
                threading.Thread(target=self.handle_tcp_client,
                                 args=(client_sock, addr), daemon=True).start()
            except socket.timeout:
                continue
        server_socket.close()

    def start_udp_server(self):
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.bind((self.host, self.udp_port))
        udp_socket.settimeout(1.0)
        print(f"[UDP] Сервер запущен на {self.host}:{self.udp_port}")

        while self.running:
            try:
                data, addr = udp_socket.recvfrom(1024)
                msg = data.decode('utf-8')
                print(f"[UDP {addr}] {msg}")
                udp_socket.sendto(data, addr)
                if msg.lower() == 'shutdown':
                    self.running = False
            except socket.timeout:
                continue
        udp_socket.close()

    def stop(self):
        self.running = False
        print("\nСервер остановлен.")


if __name__ == "__main__":
    server = SecureServer()
    threading.Thread(target=server.start_tcp_server, daemon=True).start()
    threading.Thread(target=server.start_udp_server, daemon=True).start()
    print("\n=== СЕРВЕР РАБОТАЕТ (Ctrl+C для выхода) ===\n")
    try:
        while server.running:
            threading.Event().wait(1)
    except KeyboardInterrupt:
        server.stop()
