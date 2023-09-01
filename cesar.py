import sys

def cifrar_cesar(texto, corrimiento):
    resultado = ""
    for caracter in texto:
        if caracter.isalpha():
            if caracter.isupper():
                ascii_inicio = ord('A')
            else:
                ascii_inicio = ord('a')
            codigo_cifrado = (ord(caracter) - ascii_inicio + corrimiento) % 26 + ascii_inicio
            caracter_cifrado = chr(codigo_cifrado)
            resultado += caracter_cifrado
        else:
            resultado += caracter
    return resultado

if len(sys.argv) != 3:
    print("Uso: python programa.py <texto> <corrimiento>")
    sys.exit(1)

texto = sys.argv[1]
corrimiento = int(sys.argv[2])

texto_cifrado = cifrar_cesar(texto, corrimiento)
print("Texto cifrado:", texto_cifrado)
