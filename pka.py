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
