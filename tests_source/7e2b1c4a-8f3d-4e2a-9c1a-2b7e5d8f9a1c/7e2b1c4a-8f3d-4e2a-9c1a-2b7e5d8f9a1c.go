/*
Prueba de simulacion de creacion de un archivo .txt
donde se muestra a un usuario para que este piense que su computador 
ha sido comprometido y debe reportarlo al equipo de seguridad de la informacion.
*/
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

func getDesktopPath() string {
	pub := os.Getenv("PUBLIC")
	if pub == ""{
		pub = "C:\\Users\\Public"
	}
	return filepath.Dir(pub)
}

func createAlertFile() (string, error) {
	targetPath := getDesktopPath()
	filePath := filepath.Join(targetPath, "Instrucciones.txt")
	mensaje :=`
=================================================================
                    SAFEPAY RANSOMWARE
=================================================================
¡Todos sus archivos han sido encriptados! :(

Sus archivos, así como los datos de la empresa almacenados en esta computadora, han sido cifrados con un algoritmo de grado militar. La clave de descifrado privada se encuentra en un servidor secreto y nadie puede recuperar la información sin pagar por ella.

¿QUÉ SUCEDIÓ?
Sus documentos, fotos, videos, bases de datos y otra información importante ya no son accesibles. No pierda tiempo buscando una solución, ya que solo nuestro servicio de descifrado puede recuperar sus archivos.

¿CÓMO RECUPERAR LOS ARCHIVOS?
Para recuperar sus archivos, debe realizar un pago de 0.5 Bitcoin a la siguiente dirección:
1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

Una vez realizado el pago, envíe el ID de su computadora a: safepay@darkweb.onion

Su ID de computadora: 682298

¡ADVERTENCIAS! 

No intente descifrar los archivos por su cuenta.

No contacte a empresas de recuperación de datos.

No reinicie ni reinstale el sistema operativo.

Sus archivos se perderán permanentemente si no sigue estas instrucciones.

Tiene 72 horas para realizar el pago.`
	return filePath, os.WriteFile(filePath, []byte(mensaje), 0644)
}

func openAlertFile(filePath string){
	for i := 0; i < 2; i++ {
		cmd := exec.Command("cmd", "/C", "start", "","/MAX","notepad", filePath)
		cmd.Run()
		time.Sleep(5 * time.Second)
	}
}

func main() {
	// Creando y abriendo el archivo de alerta
	filePath, err := createAlertFile()
	if err != nil {
		fmt.Printf("Error al crear el archivo: %v\n", err)
		return
	}
	fmt.Println("Archivo creado: ", filePath)
	fmt.Println("Encryptando datos de este usuario...")
	openAlertFile(filePath)
}
