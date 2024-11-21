import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Fungsi untuk mengkonversi string ke biner
def string_to_binary(s):
    return ''.join(format(ord(c), '08b') for c in s)

# Fungsi untuk mengkonversi biner ke string
def binary_to_string(b):
    chars = [chr(int(b[i:i+8], 2)) for i in range(0, len(b), 8)]
    return ''.join(chars)

# Fungsi untuk mengkonversi biner ke hexadecimal
def binary_to_hex(b):
    return hex(int(b, 2))[2:].zfill(len(b) // 4)

# Fungsi untuk mengkonversi hexadecimal ke biner
def hex_to_binary(h):
    return bin(int(h, 16))[2:].zfill(len(h) * 4)

# Padding untuk membuat panjang string kelipatan 8 bit
def pad(text):
    padding_len = 8 - (len(text) % 8)
    return text + chr(padding_len) * padding_len

# Menghapus padding setelah dekripsi
def unpad(text):
    padding_len = ord(text[-1])
    return text[:-padding_len]

# Permutasi umum
def permute(block, table):
    return ''.join([block[i - 1] for i in table])

# XOR dua biner string
def xor(a, b):
    return ''.join(['0' if i == j else '1' for i, j in zip(a, b)])

# Fungsi S-box
def s_box(block):
    sboxes = [
        # S-box 1
        [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
        # S-box 2
        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
         [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
        # S-box 3
        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
        # S-box 4
        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
         [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
         [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
        # S-box 5
        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
        # S-box 6
        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
        # S-box 7
        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
        # S-box 8
        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
    ]

    result = ""
    for i in range(8):
        row = int(block[i*6] + block[i*6+5], 2)
        col = int(block[i*6+1:i*6+5], 2)
        result += f'{sboxes[i][row][col]:04b}'
    return result

# Fungsi untuk melakukan pergeseran
def shift_left(block, num_shifts):
    return block[num_shifts:] + block[:num_shifts]

# Fungsi F
def function_f(right, key):
    expansion_table = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
                       8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
                       16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
                       24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

    p_box = [16, 7, 20, 21, 29, 12, 28, 17,
             1, 15, 23, 26, 5, 18, 31, 10,
             2, 8, 24, 14, 32, 27, 3, 9,
             19, 13, 30, 6, 22, 11, 4, 25]

    expanded_right = permute(right, expansion_table)
    xor_result = xor(expanded_right, key)
    sbox_result = s_box(xor_result)
    return permute(sbox_result, p_box)

# Fungsi putaran
def des_round(left, right, key):
    new_right = xor(left, function_f(right, key))
    return right, new_right

# Key scheduling untuk menghasilkan subkey
def key_schedule(key):
    # Key permutasi PC-1 untuk mengubah kunci 64 bit menjadi 56 bit
    pc1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
           10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
           63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
           14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]

    # Key permutasi PC-2 untuk menghasilkan subkunci 48 bit dari 56 bit
    pc2 = [14, 17, 11, 24, 1, 5, 3, 28,
           15, 6, 21, 10, 23, 19, 12, 4,
           26, 8, 16, 7, 27, 20, 13, 2,
           41, 52, 31, 37, 47, 55, 30, 40,
           51, 45, 33, 48, 44, 49, 39, 56,
           34, 53, 46, 42, 50, 36, 29, 32]

    shift_table = [1, 1, 2, 2, 2, 2, 2, 2,
                   1, 2, 2, 2, 2, 2, 2, 1]

    permuted_key = permute(key, pc1)
    left, right = permuted_key[:28], permuted_key[28:]

    subkeys = []
    for shift in shift_table:
        left = shift_left(left, shift)
        right = shift_left(right, shift)
        combined_key = left + right
        subkeys.append(permute(combined_key, pc2))

    return subkeys

def des_encrypt(plaintext, key):
    initial_permutation_table = [58, 50, 42, 34, 26, 18, 10, 2,
                                 60, 52, 44, 36, 28, 20, 12, 4,
                                 62, 54, 46, 38, 30, 22, 14, 6,
                                 64, 56, 48, 40, 32, 24, 16, 8,
                                 57, 49, 41, 33, 25, 17, 9, 1,
                                 59, 51, 43, 35, 27, 19, 11, 3,
                                 61, 53, 45, 37, 29, 21, 13, 5,
                                 63, 55, 47, 39, 31, 23, 15, 7]

    final_permutation_table = [40, 8, 48, 16, 56, 24, 64, 32,
                               39, 7, 47, 15, 55, 23, 63, 31,
                               38, 6, 46, 14, 54, 22, 62, 30,
                               37, 5, 45, 13, 53, 21, 61, 29,
                               36, 4, 44, 12, 52, 20, 60, 28,
                               35, 3, 43, 11, 51, 19, 59, 27,
                               34, 2, 42, 10, 50, 18, 58, 26,
                               33, 1, 41, 9, 49, 17, 57, 25]

    block = permute(plaintext, initial_permutation_table)
    left, right = block[:32], block[32:]

    subkeys = key_schedule(key)

    for i, subkey in enumerate(subkeys):
        left, right = des_round(left, right, subkey)

    final_block = permute(right + left, final_permutation_table)
    return final_block

def des_decrypt(ciphertext, key):
    initial_permutation_table = [58, 50, 42, 34, 26, 18, 10, 2,
                                 60, 52, 44, 36, 28, 20, 12, 4,
                                 62, 54, 46, 38, 30, 22, 14, 6,
                                 64, 56, 48, 40, 32, 24, 16, 8,
                                 57, 49, 41, 33, 25, 17, 9, 1,
                                 59, 51, 43, 35, 27, 19, 11, 3,
                                 61, 53, 45, 37, 29, 21, 13, 5,
                                 63, 55, 47, 39, 31, 23, 15, 7]

    final_permutation_table = [40, 8, 48, 16, 56, 24, 64, 32,
                               39, 7, 47, 15, 55, 23, 63, 31,
                               38, 6, 46, 14, 54, 22, 62, 30,
                               37, 5, 45, 13, 53, 21, 61, 29,
                               36, 4, 44, 12, 52, 20, 60, 28,
                               35, 3, 43, 11, 51, 19, 59, 27,
                               34, 2, 42, 10, 50, 18, 58, 26,
                               33, 1, 41, 9, 49, 17, 57, 25]

    block = permute(ciphertext, initial_permutation_table)
    left, right = block[:32], block[32:]

    subkeys = key_schedule(key)

    subkeys.reverse()

    for i, subkey in enumerate(subkeys):
        left, right = des_round(left, right, subkey)

    final_block = permute(right + left, final_permutation_table)
    return final_block

# Enkripsi string
def des_encrypt_string(plaintext, key):
    plaintext = pad(plaintext)
    binary_plaintext = string_to_binary(plaintext)
    binary_key = string_to_binary(key[:8])

    ciphertext = ""
    for i in range(0, len(binary_plaintext), 64):
        block = binary_plaintext[i:i+64].ljust(64, '0')
        encrypted_block = des_encrypt(block, binary_key)
        ciphertext += encrypted_block

    hex_ciphertext = binary_to_hex(ciphertext)
    return hex_ciphertext

# Dekripsi string
def des_decrypt_string(ciphertext, key):
    binary_ciphertext = hex_to_binary(ciphertext)
    binary_key = string_to_binary(key[:8])

    plaintext = ""
    for i in range(0, len(binary_ciphertext), 64):
        block = binary_ciphertext[i:i+64].ljust(64, '0')
        decrypted_block = des_decrypt(block, binary_key)
        plaintext += decrypted_block

    return unpad(binary_to_string(plaintext))

# plaintext = "Informatika22"
# key = "Informatika" 

# encrypted_text = des_encrypt_string(plaintext, key)
# print(f"Enkripsi: {encrypted_text}")

# decrypted_text = des_decrypt_string(encrypted_text, key)
# print(f"Dekripsi: {decrypted_text}")

import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Fungsi untuk mendaftarkan kunci publik ke PKA
def register_public_key_to_pka(public_key):
    host = '127.0.0.1'  # Alamat PKA
    port = 6000         # Port PKA

    client_socket = socket.socket()
    client_socket.connect((host, port))
    
    # Kirim kunci publik ke PKA
    client_socket.send(public_key)
    print("Kunci publik berhasil didaftarkan ke PKA.")
    
    client_socket.close()

# Fungsi RSA Dekripsi
def rsa_decrypt(encrypted_key, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(encrypted_key)

def server_program():
    host = '127.0.0.1'
    port = 5000

    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(1)

    # Generate RSA keys (private and public)
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey().export_key()

    # Daftarkan kunci publik ke PKA
    register_public_key_to_pka(public_key)

    print("Menunggu koneksi dari klien...")
    conn, address = server_socket.accept()
    print("Koneksi dari:", address)

    # Terima kunci DES terenkripsi
    encrypted_key = conn.recv(256)  # RSA key size is 2048 bits, i.e., 256 bytes
    des_key = rsa_decrypt(encrypted_key, private_key).decode()  # Dekripsi RSA dan ubah menjadi string
    print("Kunci DES diterima dan didekripsi:", des_key)

    # Terima data terenkripsi
    encrypted_data = conn.recv(1024).decode()  # Diterima dalam format string heksadesimal
    decrypted_data = des_decrypt_string(encrypted_data, des_key)  # Dekripsi dengan DES buatan
    print("Data setelah dekripsi:", decrypted_data)

    conn.close()

if __name__ == "__main__":
    server_program()
