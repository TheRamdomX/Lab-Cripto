"""
genera un codigo de python que haga cifrado de cesar donde se pueda ingresar el string a cifrar y luego el corrimiento. 
por ultimo se imprima el resultado. Es un requisito que los imputs los reciba por la linea de comandos
"""

import sys

def cifrado_cesar(texto, corrimiento):
    resultado = ""
    for char in texto:
        if char.isalpha():  # Solo ciframos letras
            base = ord('A') if char.isupper() else ord('a')
            resultado += chr((ord(char) - base + corrimiento) % 26 + base)
        else:
            resultado += char  # Mantener espacios y otros caracteres
    return resultado

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python cesar.py <texto> <corrimiento>")
        sys.exit(1)

    texto = sys.argv[1]
    corrimiento = int(sys.argv[2])

    cifrado = cifrado_cesar(texto, corrimiento)
    print(cifrado)


"""
python3 Actividad_1.py "criptografia y seguridad en redes" 9
"""