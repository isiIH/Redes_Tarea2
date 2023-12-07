Para ejecutar el código realice lo siguiente:

1. Ejecutar make en la terminal.

2. Probar alguno de los 3 algoritmos de encriptación de la siguiente manera: 
        `./rsa <filename> $((2**n))`
        `./aes <filename> $((2**n))`
        `./salsa <filename> $((2**n))`

        siendo 2**n el tamaño del archivo que desea encriptar.

Nota: Puede cambiar la variable PRINT a 0 si no quiere imprimir los textos ni el archivo encriptado, sólo mostrará los tiempos de ejecución. 

También puede generar un archivo de 1 GB ejecutando: `python3 generate_data.py` y colocarlo en la carpeta "test"