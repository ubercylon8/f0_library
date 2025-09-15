//go:build windows
// +build windows

/*
ID: 7e2b1c4a-8f3d-4e2a-9c1a-2b7e5d8f9a1c
NAME: SafePay for Users - Social Engineering Simulation
TECHNIQUE: Social Engineering Awareness
UNIT: response
CREATED: 2025-09-15 00:00:00.000000
DESCRIPTION: Simula la creación y apertura de un archivo de alerta para evaluar la capacidad de reporte de los usuarios.
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
	userProfile := os.Getenv("USERPROFILE")
	return filepath.Join(userProfile, "Desktop")
}

func createAlertFile() (string, error) {
	desktop := getDesktopPath()
	filePath := filepath.Join(desktop, "ALERTA_COMPROMETIDA.txt")
	mensaje := "Tu PC ha sido comprometida. Por favor, reporta este comportamiento inmediatamente al equipo de Seguridad de la Información."
	return filePath, os.WriteFile(filePath, []byte(mensaje), 0644)
}

func openAlertFile(filePath string) error {
	cmd := exec.Command("cmd", "/C", "start", "", filePath)
	return cmd.Run()
}

func main() {
	fmt.Println("SafePay for Users - Social Engineering Simulation")
	fmt.Println("Creando archivo de alerta en el escritorio...")
	filePath, err := createAlertFile()
	if err != nil {
		fmt.Printf("Error al crear el archivo: %v\n", err)
		return
	}
	fmt.Println("Archivo creado: ", filePath)
	fmt.Println("Abriendo archivo para el usuario...")
	err = openAlertFile(filePath)
	if err != nil {
		fmt.Printf("Error al abrir el archivo: %v\n", err)
		return
	}
	fmt.Println("Archivo de alerta abierto exitosamente.")
	fmt.Println("Esperando reacción del usuario...")
	time.Sleep(30 * time.Second)
	fmt.Println("Fin de la simulación. Registrar si el usuario reportó el incidente.")
}
