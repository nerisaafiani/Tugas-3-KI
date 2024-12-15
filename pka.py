<<<<<<< HEAD
import socket

def pka_server_program():
    host = '127.0.0.1'  # Alamat server PKA
    port = 6000         # Port untuk PKA

    # Buat server socket
    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(5)

    # Dictionary untuk menyimpan kunci publik
    public_keys = {}

    print("PKA berjalan. Menunggu permintaan dari server atau klien...")

    while True:
        try:
            # Terima koneksi dari server atau klien
            conn, address = server_socket.accept()
            print(f"Koneksi diterima dari: {address}")

            # Terima data
            data = conn.recv(2048).decode()  # Terima data dalam format string
            print(f"Data diterima: {data}")

            if data.startswith("STORE:"):  # Penyimpanan kunci publik
                try:
                    _, entity_id, public_key = data.split(":")
                    public_keys[entity_id] = public_key
                    print(f"Kunci publik dari '{entity_id}' berhasil disimpan.")
                    conn.send(b"Public key stored successfully.")
                except ValueError:
                    conn.send(b"Error: Invalid STORE command format.")
                    print("Error: Format perintah STORE tidak valid.")

            elif data.startswith("REQUEST:"):  # Permintaan kunci publik
                try:
                    _, entity_id = data.split(":")
                    if entity_id in public_keys:
                        conn.send(public_keys[entity_id].encode())
                        print(f"Kunci publik untuk '{entity_id}' berhasil dikirim.")
                    else:
                        conn.send(b"Error: Public key not found.")
                        print(f"Error: Kunci publik untuk '{entity_id}' tidak ditemukan.")
                except ValueError:
                    conn.send(b"Error: Invalid REQUEST command format.")
                    print("Error: Format perintah REQUEST tidak valid.")

            else:
                conn.send(b"Error: Invalid command.")
                print(f"Error: Perintah tidak dikenali: {data}")

            conn.close()

        except KeyboardInterrupt:
            print("\nPKA dihentikan secara manual.")
            break
        except Exception as e:
            print(f"Error: {e}")

    server_socket.close()

if __name__ == "__main__":
    pka_server_program()
=======
import socket
from Crypto.PublicKey import RSA

def pka_server_program():
    host = '127.0.0.1'  # Alamat server PKA
    port = 6000         # Port untuk PKA

    # Buat server socket
    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(5)  # Izinkan hingga 5 koneksi dalam antrean

    # Muat kunci publik server RSA dari file
    try:
        with open("public_key.pem", "rb") as f:
            public_key = f.read()
    except FileNotFoundError:
        print("Error: File public_key.pem tidak ditemukan.")
        return

    print("PKA berjalan. Menunggu permintaan klien...")

    while True:
        try:
            # Terima koneksi dari klien
            conn, address = server_socket.accept()
            print(f"Koneksi diterima dari: {address}")

            # Kirimkan kunci publik ke klien
            conn.send(public_key)
            print(f"Kunci publik dikirim ke: {address}")

            # Tutup koneksi dengan klien
            conn.close()
        except KeyboardInterrupt:
            print("\nPKA dihentikan secara manual.")
            break
        except Exception as e:
            print(f"Error: {e}")

    # Tutup server socket
    server_socket.close()

if __name__ == "__main__":
    pka_server_program()
>>>>>>> ecc7e329da9900bd3327451a48401f4dc8475368
