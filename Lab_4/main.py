from Crypto.Cipher import AES, DES, DES3
from Crypto.Util.Padding import pad, unpad
import base64
import secrets, string

RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[36m"
MAGENTA = "\033[35m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
BLUE = "\033[34m"
RED = "\033[31m"
WHITE = "\033[97m"


def encrypt(data, key, iv, algorithm="DES"):
    if algorithm == "AES":
        cipher = AES.new(key, AES.MODE_CBC, iv)
        cipher_text = cipher.encrypt(pad(data, AES.block_size))

    elif algorithm == "DES":
        cipher = DES.new(key, DES.MODE_CBC, iv)
        cipher_text = cipher.encrypt(pad(data, DES.block_size))

    elif algorithm == "3DES":
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        cipher_text = cipher.encrypt(pad(data, DES3.block_size))    

    else:
        raise ValueError("Opción no válida.")
    
    encoded_cipher_text = base64.b64encode(cipher_text)
    return encoded_cipher_text.decode('utf-8')


def decrypt(encoded_cipher_text, key, iv, algorithm="DES"):
    cipher_text = base64.b64decode(encoded_cipher_text)
    
    if algorithm == "AES":
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(cipher_text), AES.block_size)
        
    elif algorithm == "DES":
        cipher = DES.new(key, DES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(cipher_text), DES.block_size)
        
    elif algorithm == "3DES":
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(cipher_text), DES3.block_size)
        
    else:
        raise ValueError("Algoritmo no soportado")
    
    return decrypted_data.decode('utf-8')


def print_message(m, size, key, new_key, type):
    adj = "se utilizará un random padding" if m == "menor" else "se truncará"
    color = YELLOW if m == "menor" else RED

    print(f"{color}{BOLD}{type} {m} al tamaño requerido ({size} bytes), {adj}.{RESET}")
    print(f"{CYAN}{type} original:{RESET} {key}")
    print(f"{GREEN}{type} ajustada:{RESET} {new_key}\n")


def adjust_key(key, size, type):
    if len(key) < size:
        random_padding = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(size - len(key)))
        new_key = (key + random_padding.encode('utf-8'))[:size]  
        print_message("menor", size, key, new_key, type)

    elif len(key) > size:
        new_key = key[:size]
        print_message("mayor", size, key, new_key, type)
    
    else:
        new_key = key
    
    return new_key


def input_key_iv(type=""):
    key = input(f"Llave {type}: ").encode()
    iv = input(f"IV {type}: ").encode()
    return key, iv


def encrypt_and_print(data, key, iv, algorithm, key_size, iv_size):
    print(f"\n{MAGENTA}{BOLD}== {algorithm} =={RESET}")
    adj_key = adjust_key(key, key_size, "Llave")
    adj_IV = adjust_key(iv, iv_size, "IV")

    encoded_text = encrypt(data, adj_key, adj_IV, algorithm)
    print(f"{BLUE}Texto cifrado {algorithm}:{RESET} {GREEN}{encoded_text}{RESET}")

    return encoded_text, adj_key, adj_IV


def decrypt_and_print(encoded_cipher_text, key, iv, algorithm, key_size, iv_size):
    print(f"\n{MAGENTA}{BOLD}== {algorithm} (Descifrado) =={RESET}")

    print(f"{BLUE}Texto cifrado:{RESET} {encoded_cipher_text}")
    print(f"{CYAN}Llave:{RESET} {key}")
    print(f"{CYAN}IV:{RESET} {iv}\n")

    decrypted_text = decrypt(encoded_cipher_text, adjust_key(key, key_size, "Llave"), adjust_key(iv, iv_size, "IV"), algorithm)
    print(f"{GREEN}Texto descifrado {algorithm}:{RESET} {BOLD}{decrypted_text}{RESET}") 


def process_data(option, data):
    # (algorithm, key_size, iv_size)
    algorithms = [
        ("AES", 32, 16),
        ("DES", 8, 8),
        ("3DES", 24, 8)
    ]

    encrypted_data = []

    if option == "s":
        key, iv = input_key_iv("Todos los algoritmos")
        
        print(f"\n{MAGENTA}{BOLD}=== CIFRADO ==={RESET}\n")
        print(f"{BLUE}Texto original:{RESET} {data.decode()}")

        for algorithm, key_size, iv_size in algorithms:
            encrypted, key_out, iv_out = encrypt_and_print(data, key, iv, algorithm, key_size, iv_size)
            encrypted_data.append((encrypted, key_out, iv_out, algorithm, key_size, iv_size))

    else:
        keys_iv = {}
        
        for algorithm, key_size, iv_size in algorithms:
            key, iv = input_key_iv(algorithm)
            keys_iv[algorithm] = (key, iv)
            print("\n")    

        print(f"\n{MAGENTA}{BOLD}=== CIFRADO ==={RESET}\n")
        print(f"{BLUE}Texto original:{RESET} {data.decode()}")

        for algorithm, key_size, iv_size in algorithms:
            key, iv = keys_iv[algorithm]
            encrypted, key_out, iv_out = encrypt_and_print(data, key, iv, algorithm, key_size, iv_size)
            encrypted_data.append((encrypted, key_out, iv_out, algorithm, key_size, iv_size))

    print(f"\n{MAGENTA}{BOLD}=== DESCIFRADO ==={RESET}\n")
    for encrypted, key_out, iv_out, algorithm, key_size, iv_size in encrypted_data:
        decrypt_and_print(encrypted, key_out, iv_out, algorithm, key_size, iv_size)


def main():
    print(f"\n{MAGENTA}{BOLD}=== CIFRADO Y DESCIFRADO (AES / DES / 3DES) ==={RESET}\n")

    print(f"{WHITE}¿Utilizar la misma llave/IV para todos los algoritmos? (s/n){RESET}")
    while True:
        option = input("s/n: ").lower()
        if option in ["s", "n"]:
            break
        print(f"{RED}Opción no válida.{RESET}\n")

    data = input(f"\n{WHITE}Texto a encriptar:{RESET} ").encode()
    process_data(option, data)


if __name__ == "__main__":
    main()
