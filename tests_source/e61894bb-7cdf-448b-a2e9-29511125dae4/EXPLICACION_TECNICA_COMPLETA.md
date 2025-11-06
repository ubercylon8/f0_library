# Explicación Técnica Completa - Test Qilin Cross-Platform Evasion

## Índice
1. [Resumen General](#resumen-general)
2. [Análisis del Archivo Go Principal](#análisis-del-archivo-go-principal)
3. [Análisis del Script WSL PowerShell](#análisis-del-script-wsl-powershell)
4. [Análisis del Payload Linux](#análisis-del-payload-linux)
5. [Análisis del Harvester de Credenciales](#análisis-del-harvester-de-credenciales)
6. [Flujo de Ejecución Completo](#flujo-de-ejecución-completo)
7. [Técnicas de Evasión Implementadas](#técnicas-de-evasión-implementadas)

---

## Resumen General

Este test simula las técnicas avanzadas del ransomware Qilin que utiliza binarios de Linux ejecutados en Windows a través de WSL (Windows Subsystem for Linux) para evadir las soluciones EDR tradicionales. El test está diseñado para evaluar la capacidad de detección de sistemas de seguridad contra ataques multiplataforma.

**Fases del Ataque Simulado:**
1. Verificación e instalación de WSL
2. Ejecución de payload Linux via WSL
3. Harvesting de credenciales
4. Ataque BYOVD (Bring Your Own Vulnerable Driver)
5. Movimiento lateral multiplataforma

---

## Análisis del Archivo Go Principal

### Estructura y Imports

```go
//go:build windows
// +build windows
```
**Explicación**: Estas directivas de compilación aseguran que el código solo se compile y ejecute en sistemas Windows, ya que el test está específicamente diseñado para evaluar la evasión en entornos Windows.

```go
/*
ID: e61894bb-7cdf-448b-a2e9-29511125dae4
NAME: Qilin Cross-Platform Evasion Simulation
TECHNIQUE: T1202, T1055, T1574.002, T1003, T1046, T1082
UNIT: response
CREATED: 2025-11-03 00:00:00.000000
*/
```
**Explicación**: Metadatos del test que incluyen:
- **ID único**: Para identificación en el sistema F0RT1KA
- **Técnicas MITRE ATT&CK**: Mapeo de las técnicas de ataque simuladas
- **Unidad**: Tipo de test (response = test de respuesta de seguridad)

```go
import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	Dropper "github.com/preludeorg/libraries/go/tests/dropper"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)
```
**Explicación de imports**:
- `_ "embed"`: Permite embebir archivos en el binario compilado
- Librerías estándar para manejo de archivos, procesos y tiempo
- **Dropper/Endpoint**: Librerías F0RT1KA para simulación y logging

### Archivos Embebidos

```go
//go:embed wsl_verification.ps1
var wslVerificationScript []byte

//go:embed linux_payload.sh
var linuxPayload []byte

//go:embed credential_harvester.ps1
var credentialHarvester []byte

//go:embed rwdrv.sys
var vulnerableDriver []byte
```
**Explicación**: Estos archivos se embeben en el binario compilado, evitando la necesidad de archivos externos y aumentando la portabilidad del test. Simula cómo el malware real integra todos sus componentes en un solo ejecutable.

### Función checkWSLInstallation()

```go
func checkWSLInstallation() (bool, error) {
	cmd := exec.Command("wsl", "--status")
	output, err := cmd.Output()
	if err != nil {
		return false, err
	}
	
	// Check if WSL is installed and has a distribution
	if strings.Contains(string(output), "Default Version") {
		// Verify we can execute basic commands
		testCmd := exec.Command("wsl", "echo", "test")
		_, err := testCmd.Output()
		return err == nil, nil
	}
	
	return false, fmt.Errorf("WSL not properly configured")
}
```
**Explicación línea por línea**:
- **Línea 2**: Ejecuta `wsl --status` para verificar el estado de WSL
- **Línea 3-6**: Captura la salida del comando y maneja errores
- **Línea 8-12**: Busca "Default Version" en la salida, indicando WSL instalado
- **Línea 10-11**: Test adicional ejecutando un comando simple en WSL
- **Línea 15**: Retorna error si WSL no está configurado correctamente

**Propósito**: Esta función implementa la verificación requerida de WSL antes de proceder con el ataque multiplataforma.

### Función installWSL()

```go
func installWSL() error {
	Endpoint.Say("WSL not detected, attempting installation...")
	
	// Enable WSL feature
	cmd := exec.Command("dism.exe", "/online", "/enable-feature", "/featurename:Microsoft-Windows-Subsystem-Linux", "/all", "/norestart")
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to enable WSL feature: %v", err)
	}
	
	// Install default Ubuntu distribution
	installCmd := exec.Command("wsl", "--install", "-d", "Ubuntu")
	err = installCmd.Run()
	if err != nil {
		return fmt.Errorf("failed to install WSL distribution: %v", err)
	}
	
	Endpoint.Say("WSL installation initiated - may require reboot")
	return nil
}
```
**Explicación línea por línea**:
- **Línea 2**: Log del intento de instalación
- **Línea 4-5**: Usa DISM para habilitar la característica WSL de Windows
- **Línea 6-8**: Manejo de errores de habilitación
- **Línea 10-11**: Instala la distribución Ubuntu por defecto
- **Línea 12-14**: Manejo de errores de instalación
- **Línea 16**: Notifica que puede requerir reinicio

**Propósito**: Simula la instalación automática de WSL que haría un atacante para establecer el entorno necesario para la evasión multiplataforma.

### Función executeLinuxPayload()

```go
func executeLinuxPayload() error {
	Endpoint.Say("Phase 2: Executing Linux binary via WSL...")
	
	// Create Linux script in WSL filesystem
	scriptPath := "/tmp/qilin_payload.sh"
	
	// Write the payload to WSL filesystem
	writeCmd := exec.Command("wsl", "bash", "-c", fmt.Sprintf("cat > %s", scriptPath))
	writeCmd.Stdin = strings.NewReader(string(linuxPayload))
	err := writeCmd.Run()
	if err != nil {
		return fmt.Errorf("failed to write Linux payload: %v", err)
	}
	
	// Make it executable
	chmodCmd := exec.Command("wsl", "chmod", "+x", scriptPath)
	err = chmodCmd.Run()
	if err != nil {
		return fmt.Errorf("failed to make payload executable: %v", err)
	}
	
	// Execute the payload
	execCmd := exec.Command("wsl", "bash", scriptPath)
	output, err := execCmd.CombinedOutput()
	if err != nil {
		Endpoint.Say("Linux payload execution blocked: %v", err)
		return err
	}
	
	Endpoint.Say("Linux payload executed successfully via WSL")
	Endpoint.Say("Output: %s", string(output))
	return nil
}
```
**Explicación línea por línea**:
- **Línea 4**: Define la ruta del script en el filesystem de Linux (/tmp)
- **Línea 6-7**: Crea comando para escribir el payload usando redirección de cat
- **Línea 8**: Configura el stdin con el contenido del payload embebido
- **Línea 9-12**: Ejecuta y maneja errores de escritura
- **Línea 14-18**: Hace el script ejecutable usando chmod +x
- **Línea 20-21**: Ejecuta el payload Linux via WSL bash
- **Línea 22-26**: Maneja la ejecución y captura errores (EDR blocking)
- **Línea 28-29**: Reporta éxito y muestra salida

**Propósito**: Esta es la técnica central del test - ejecutar código Linux a través de WSL para evadir EDRs enfocados en Windows.

### Función harvestCredentials()

```go
func harvestCredentials() error {
	Endpoint.Say("Phase 3: Simulating credential harvesting...")
	
	targetDir := "c:\\F0"
	scriptPath := filepath.Join(targetDir, "cred_harvest.ps1")
	
	err := os.WriteFile(scriptPath, credentialHarvester, 0644)
	if err != nil {
		return fmt.Errorf("failed to drop credential harvester: %v", err)
	}
	
	cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-File", scriptPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		Endpoint.Say("Credential harvesting blocked: %v", err)
		return err
	}
	
	Endpoint.Say("Credential harvesting simulation completed")
	Endpoint.Say("Harvested data: %s", string(output))
	return nil
}
```
**Explicación línea por línea**:
- **Línea 3-4**: Define directorio objetivo y ruta del script de harvesting
- **Línea 6-9**: Escribe el script embebido al disco
- **Línea 11**: Ejecuta PowerShell con bypass de execution policy
- **Línea 12-16**: Captura salida y maneja bloqueo por EDR
- **Línea 18-19**: Reporta éxito y muestra datos "robados"

**Propósito**: Simula el robo de credenciales específicas que Qilin busca (Veeam, SQL, domain admin).

### Función byovdAttack()

```go
func byovdAttack() error {
	Endpoint.Say("Phase 4: BYOVD attack with vulnerable driver...")
	
	targetDir := "c:\\F0"
	driverPath := filepath.Join(targetDir, "rwdrv.sys")
	
	err := os.WriteFile(driverPath, vulnerableDriver, 0755)
	if err != nil {
		return fmt.Errorf("failed to drop vulnerable driver: %v", err)
	}
	
	// Attempt to load the driver
	loadCmd := exec.Command("sc", "create", "rwdrv", "binPath=", driverPath, "type=", "kernel")
	err = loadCmd.Run()
	if err != nil {
		Endpoint.Say("Driver loading blocked: %v", err)
		return err
	}
	
	startCmd := exec.Command("sc", "start", "rwdrv")
	err = startCmd.Run()
	if err != nil {
		Endpoint.Say("Driver start blocked: %v", err)
		return err
	}
	
	Endpoint.Say("Vulnerable driver loaded successfully")
	
	// Cleanup
	exec.Command("sc", "stop", "rwdrv").Run()
	exec.Command("sc", "delete", "rwdrv").Run()
	
	return nil
}
```
**Explicación línea por línea**:
- **Línea 3-4**: Define directorio y ruta del driver vulnerable
- **Línea 6-9**: Escribe el driver embebido al disco
- **Línea 11-16**: Intenta crear servicio para el driver usando sc.exe
- **Línea 18-23**: Intenta iniciar el driver
- **Línea 25**: Reporta éxito de carga
- **Línea 27-28**: Limpieza del driver (stop y delete)

**Propósito**: Simula ataque BYOVD donde se carga un driver firmado pero vulnerable para obtener acceso kernel.

### Función lateralMovement()

```go
func lateralMovement() error {
	Endpoint.Say("Phase 5: Cross-platform lateral movement simulation...")
	
	// Simulate network reconnaissance
	reconCmd := exec.Command("wsl", "nmap", "-sn", "192.168.1.0/24")
	output, err := reconCmd.CombinedOutput()
	if err != nil {
		Endpoint.Say("Network reconnaissance blocked: %v", err)
		return err
	}
	
	Endpoint.Say("Network reconnaissance completed")
	
	// Simulate SSH connection attempts
	sshCmd := exec.Command("wsl", "ssh", "-o", "ConnectTimeout=5", "-o", "PasswordAuthentication=yes", "admin@192.168.1.1")
	sshCmd.Run() // Expected to fail, but simulates the attempt
	
	Endpoint.Say("Lateral movement simulation completed")
	return nil
}
```
**Explicación línea por línea**:
- **Línea 4-5**: Ejecuta nmap a través de WSL para reconocimiento de red
- **Línea 6-9**: Maneja bloqueo de reconocimiento por EDR
- **Línea 13-14**: Simula intento de conexión SSH (esperado a fallar)
- **Línea 16**: Reporta finalización del movimiento lateral

**Propósito**: Simula el uso de herramientas Linux para reconocimiento y movimiento lateral que pueden evadir detección Windows.

### Función Principal executeQilinSimulation()

```go
func executeQilinSimulation() error {
	targetDir := "c:\\F0"
	os.MkdirAll(targetDir, 0755)
	
	// Phase 1: WSL Verification and Installation
	Endpoint.Say("Phase 1: WSL verification and setup...")
	wslInstalled, err := checkWSLInstallation()
	if err != nil || !wslInstalled {
		Endpoint.Say("WSL not available, attempting installation...")
		
		// Drop WSL verification script
		scriptPath := filepath.Join(targetDir, "wsl_verification.ps1")
		err := os.WriteFile(scriptPath, wslVerificationScript, 0644)
		if err != nil {
			return fmt.Errorf("failed to drop WSL script: %v", err)
		}
		
		// Execute WSL verification/installation script
		cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-File", scriptPath)
		output, err := cmd.CombinedOutput()
		if err != nil {
			Endpoint.Say("WSL installation blocked: %v", err)
			return fmt.Errorf("WSL installation failed")
		}
		
		Endpoint.Say("WSL setup completed: %s", string(output))
		
		// Recheck WSL status
		wslInstalled, err = checkWSLInstallation()
		if err != nil || !wslInstalled {
			return fmt.Errorf("WSL still not available after installation")
		}
	}
	
	Endpoint.Say("WSL verification successful, proceeding with cross-platform attack...")
	
	// Execute attack phases
	phases := []struct {
		name string
		fn   func() error
	}{
		{"Linux Payload Execution", executeLinuxPayload},
		{"Credential Harvesting", harvestCredentials},
		{"BYOVD Attack", byovdAttack},
		{"Lateral Movement", lateralMovement},
	}
	
	completedPhases := 0
	for _, phase := range phases {
		Endpoint.Say("Executing %s...", phase.name)
		err := phase.fn()
		if err != nil {
			Endpoint.Say("Phase failed: %s - %v", phase.name, err)
			break
		}
		completedPhases++
		Endpoint.Say("Phase completed: %s", phase.name)
		time.Sleep(2 * time.Second)
	}
	
	if completedPhases == len(phases) {
		Endpoint.Say("SUCCESS: All Qilin cross-platform attack phases completed")
		Endpoint.Say("System is vulnerable to cross-platform evasion techniques")
		return nil
	}
	
	return fmt.Errorf("attack stopped after %d/%d phases", completedPhases, len(phases))
}
```
**Explicación línea por línea**:
- **Línea 1-2**: Crea directorio de trabajo para el test
- **Línea 4-6**: Inicia verificación de WSL
- **Línea 7-29**: Maneja instalación de WSL si no está disponible
- **Línea 31**: Confirma WSL listo para uso
- **Línea 33-40**: Define array de fases de ataque con funciones
- **Línea 42-52**: Ejecuta cada fase secuencialmente, parando si falla alguna
- **Línea 54-58**: Evalúa éxito total vs parcial del ataque
- **Línea 60**: Retorna fallo si no se completaron todas las fases

**Propósito**: Orquesta la ejecución completa del ataque multiplataforma, implementando la lógica de fases que caracteriza a Qilin.

---

## Análisis del Script WSL PowerShell

### Estructura y Propósito

```powershell
# WSL Verification and Installation Script for Qilin Simulation
# This script checks for WSL availability and installs it if needed

Write-Host "Qilin WSL Verification Starting..." -ForegroundColor Yellow
```
**Explicación**: Header del script con propósito claro y logging inicial con color para visibilidad.

### Verificación de WSL Existente

```powershell
# Check if WSL is installed
try {
    $wslStatus = wsl --status 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "WSL detected, checking distribution..." -ForegroundColor Green
        
        # Check if we have a working distribution
        $distroTest = wsl echo "WSL_TEST_OK" 2>&1
        if ($distroTest -eq "WSL_TEST_OK") {
            Write-Host "WSL is functional and ready" -ForegroundColor Green
            exit 0
        } else {
            Write-Host "WSL installed but no working distribution found" -ForegroundColor Orange
        }
    }
} catch {
    Write-Host "WSL not detected, proceeding with installation..." -ForegroundColor Red
}
```
**Explicación línea por línea**:
- **Línea 3**: Ejecuta `wsl --status` capturando stderr también
- **Línea 4**: Verifica exit code exitoso (0)
- **Línea 7**: Test funcional ejecutando echo en WSL
- **Línea 8-10**: Si el test retorna la cadena esperada, WSL está listo
- **Línea 11-12**: WSL instalado pero sin distribución funcional
- **Línea 15**: Captura cualquier excepción y procede con instalación

### Habilitación de Característica WSL

```powershell
# Enable WSL feature if not enabled
Write-Host "Enabling WSL feature..." -ForegroundColor Yellow
try {
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -All -NoRestart
    Write-Host "WSL feature enabled" -ForegroundColor Green
} catch {
    Write-Host "Failed to enable WSL feature: $($_.Exception.Message)" -ForegroundColor Red
}
```
**Explicación línea por línea**:
- **Línea 4**: Habilita la característica opcional WSL sin reinicio
- **Línea 5**: Confirma habilitación exitosa
- **Línea 7**: Captura y muestra errores de habilitación

### Instalación de WSL

```powershell
# Check if we can install WSL via winget or direct download
Write-Host "Attempting WSL installation..." -ForegroundColor Yellow
try {
    # Try modern WSL installation
    wsl --install --no-launch
    Write-Host "WSL installation completed" -ForegroundColor Green
} catch {
    Write-Host "WSL installation failed: $($_.Exception.Message)" -ForegroundColor Red
    
    # Fallback: Try to download Ubuntu manually
    Write-Host "Attempting manual Ubuntu installation..." -ForegroundColor Yellow
    try {
        Invoke-WebRequest -Uri "https://aka.ms/wslubuntu2004" -OutFile "$env:TEMP\Ubuntu.appx"
        Add-AppxPackage "$env:TEMP\Ubuntu.appx"
        Write-Host "Ubuntu distribution installed manually" -ForegroundColor Green
    } catch {
        Write-Host "Manual installation also failed: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}
```
**Explicación línea por línea**:
- **Línea 5**: Intenta instalación moderna de WSL sin lanzar
- **Línea 8-9**: Si falla, intenta método manual
- **Línea 12**: Descarga Ubuntu desde Microsoft directamente
- **Línea 13**: Instala como paquete AppX
- **Línea 16**: Sale con error si ambos métodos fallan

### Verificación Final

```powershell
# Final verification
Write-Host "Performing final WSL verification..." -ForegroundColor Yellow
try {
    $finalTest = wsl echo "INSTALLATION_SUCCESS" 2>&1
    if ($finalTest -eq "INSTALLATION_SUCCESS") {
        Write-Host "WSL installation and verification successful!" -ForegroundColor Green
        exit 0
    } else {
        Write-Host "WSL verification failed after installation" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "Final verification failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
```
**Explicación línea por línea**:
- **Línea 4**: Test final de funcionalidad WSL
- **Línea 5-7**: Si funciona correctamente, sale con éxito
- **Línea 8-10**: Si no funciona, reporta fallo
- **Línea 12-14**: Maneja excepciones y sale con error

**Propósito del Script**: Este script implementa la instalación robusta de WSL requerida, con múltiples métodos de fallback y verificación completa.

---

## Análisis del Payload Linux

### Header y Inicialización

```bash
#!/bin/bash
# Qilin Linux Payload Simulation
# This simulates the Linux binary execution that Qilin uses to evade Windows-based EDR

echo "Qilin Linux Payload Starting..."
echo "Timestamp: $(date)"
```
**Explicación**:
- **Línea 1**: Shebang para bash
- **Línea 4-5**: Logging inicial con timestamp para tracking

### Reconocimiento del Sistema

```bash
# Simulate system reconnaissance
echo "Phase: System Reconnaissance"
uname -a
id
pwd
ls -la /etc/passwd 2>/dev/null || echo "Password file access denied"
```
**Explicación línea por línea**:
- **Línea 3**: Muestra información completa del sistema (kernel, arquitectura)
- **Línea 4**: Muestra identificación del usuario actual y grupos
- **Línea 5**: Muestra directorio actual de trabajo
- **Línea 6**: Intenta listar archivo de passwords, maneja fallo silenciosamente

### Descubrimiento de Red

```bash
# Simulate network discovery
echo "Phase: Network Discovery"
ip a 2>/dev/null || ifconfig 2>/dev/null || echo "Network interfaces not accessible"
netstat -an 2>/dev/null | head -10 || ss -tuln 2>/dev/null | head -10 || echo "Network connections not accessible"
```
**Explicación línea por línea**:
- **Línea 3**: Intenta múltiples comandos para mostrar interfaces de red
- **Línea 4**: Intenta múltiples comandos para mostrar conexiones de red activas

### Enumeración de Procesos

```bash
# Simulate process enumeration
echo "Phase: Process Enumeration"
ps aux 2>/dev/null | head -10 || echo "Process enumeration blocked"
```
**Explicación**: Lista procesos del sistema, limitado a 10 para brevedad, maneja bloqueo.

### Exploración del Sistema de Archivos

```bash
# Simulate file system exploration
echo "Phase: File System Exploration"
find /home -name "*.txt" -o -name "*.doc" -o -name "*.pdf" 2>/dev/null | head -10 || echo "File search restricted"
find /var -name "*.log" 2>/dev/null | head -5 || echo "Log access restricted"
```
**Explicación línea por línea**:
- **Línea 3**: Busca archivos de documentos en directorios home
- **Línea 4**: Busca archivos de log del sistema

### Intento de Persistencia

```bash
# Simulate persistence attempt
echo "Phase: Persistence Attempt"
crontab -l 2>/dev/null || echo "Crontab access denied"
ls -la ~/.ssh/ 2>/dev/null || echo "SSH directory not accessible"
```
**Explicación línea por línea**:
- **Línea 3**: Intenta listar tareas programadas del usuario
- **Línea 4**: Intenta acceder a directorio SSH para keys

### Búsqueda de Credenciales

```bash
# Simulate credential search
echo "Phase: Credential Search"
grep -r "password" /home 2>/dev/null | head -5 || echo "Credential search blocked"
find /home -name "*.key" -o -name "*.pem" 2>/dev/null | head -5 || echo "Key file search blocked"
```
**Explicación línea por línea**:
- **Línea 3**: Busca cadenas "password" en archivos home
- **Línea 4**: Busca archivos de claves criptográficas

### Creación de Indicador

```bash
# Create indicator file
echo "QILIN_LINUX_EXECUTION_SUCCESS" > /tmp/qilin_indicator.txt
```
**Explicación**: Crea archivo indicador para confirmar ejecución exitosa.

### Simulación de Comunicación C2

```bash
# Simulate C2 communication attempt
echo "Phase: C2 Communication Simulation"
curl -s --connect-timeout 5 http://httpbin.org/get 2>/dev/null && echo "External communication successful" || echo "External communication blocked"

echo "Qilin Linux payload execution completed"
echo "Indicators: $(cat /tmp/qilin_indicator.txt 2>/dev/null || echo 'Indicator file not created')"
```
**Explicación línea por línea**:
- **Línea 3**: Intenta comunicación externa con timeout de 5 segundos
- **Línea 5**: Reporta finalización
- **Línea 6**: Muestra contenido del archivo indicador

**Propósito del Payload**: Este script simula las actividades de reconocimiento y establecimiento que haría un atacante usando herramientas Linux para evadir detección Windows.

---

## Análisis del Harvester de Credenciales

### Simulación de Robo de Credenciales Veeam

```powershell
# Simulate Veeam Backup credential theft
Write-Host "Phase: Veeam Backup Credential Simulation" -ForegroundColor Yellow
try {
    # Look for Veeam registry entries (simulation)
    $veeamKey = "HKLM:\SOFTWARE\Veeam\Veeam Backup and Replication"
    if (Test-Path $veeamKey) {
        Write-Host "Veeam installation detected" -ForegroundColor Green
        # Simulate credential extraction (safe simulation)
        Write-Host "Simulating Veeam credential extraction..."
    } else {
        Write-Host "Veeam not detected, simulating credential search in registry..." -ForegroundColor Orange
    }
} catch {
    Write-Host "Veeam credential simulation blocked: $($_.Exception.Message)" -ForegroundColor Red
}
```
**Explicación línea por línea**:
- **Línea 4**: Define ruta de registry donde Veeam almacena configuración
- **Línea 5-8**: Si existe instalación, simula extracción de credenciales
- **Línea 9-10**: Si no existe, simula búsqueda en registry
- **Línea 12**: Captura bloqueo por EDR

### Simulación de Robo SQL

```powershell
# Simulate SQL database credential theft
Write-Host "Phase: SQL Database Credential Simulation" -ForegroundColor Yellow
try {
    # Look for SQL Server instances
    $sqlServices = Get-Service | Where-Object {$_.Name -like "*SQL*"}
    if ($sqlServices) {
        Write-Host "SQL services detected: $($sqlServices.Count) services" -ForegroundColor Green
        Write-Host "Simulating SQL credential extraction..."
        
        # Simulate connection string search
        $configPaths = @(
            "$env:PROGRAMFILES\Microsoft SQL Server",
            "$env:PROGRAMFILES(x86)\Microsoft SQL Server",
            "$env:ALLUSERSPROFILE\Microsoft\SQL Server"
        )
        
        foreach ($path in $configPaths) {
            if (Test-Path $path) {
                Write-Host "Found SQL installation path: $path" -ForegroundColor Green
            }
        }
    } else {
        Write-Host "No SQL services detected" -ForegroundColor Orange
    }
} catch {
    Write-Host "SQL credential simulation blocked: $($_.Exception.Message)" -ForegroundColor Red
}
```
**Explicación línea por línea**:
- **Línea 5**: Busca servicios con "SQL" en el nombre
- **Línea 6-8**: Si encuentra servicios, simula extracción
- **Línea 10-15**: Define rutas típicas de instalación SQL
- **Línea 17-21**: Verifica cada ruta de instalación
- **Línea 24**: Captura bloqueo por EDR

### Simulación de Credenciales de Dominio

```powershell
# Simulate domain admin credential search
Write-Host "Phase: Domain Admin Credential Simulation" -ForegroundColor Yellow
try {
    # Check domain membership
    $domain = (Get-WmiObject Win32_ComputerSystem).Domain
    if ($domain -ne "WORKGROUP") {
        Write-Host "Domain environment detected: $domain" -ForegroundColor Green
        Write-Host "Simulating domain admin credential search..."
        
        # Simulate credential cache enumeration
        Write-Host "Checking credential cache..."
        cmdkey /list 2>&1 | Out-String
        
    } else {
        Write-Host "Workgroup environment detected" -ForegroundColor Orange
    }
} catch {
    Write-Host "Domain credential simulation blocked: $($_.Exception.Message)" -ForegroundColor Red
}
```
**Explicación línea por línea**:
- **Línea 5**: Obtiene nombre del dominio del sistema
- **Línea 6-12**: Si está en dominio, simula búsqueda de credenciales admin
- **Línea 11**: Enumera credenciales almacenadas en cache
- **Línea 14**: Si es workgroup, nota el ambiente

### Simulación de Credenciales del Navegador

```powershell
# Simulate browser credential theft
Write-Host "Phase: Browser Credential Simulation" -ForegroundColor Yellow
try {
    $browserPaths = @{
        "Chrome" = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
        "Edge" = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"
        "Firefox" = "$env:APPDATA\Mozilla\Firefox\Profiles"
    }
    
    foreach ($browser in $browserPaths.Keys) {
        if (Test-Path $browserPaths[$browser]) {
            Write-Host "Browser credential database found: $browser" -ForegroundColor Green
            Write-Host "Simulating $browser credential extraction..."
        }
    }
} catch {
    Write-Host "Browser credential simulation blocked: $($_.Exception.Message)" -ForegroundColor Red
}
```
**Explicación línea por línea**:
- **Línea 4-7**: Define hashtable con rutas de bases de datos de credenciales
- **Línea 9-13**: Itera sobre cada navegador y verifica si existe su DB
- **Línea 12**: Simula extracción de credenciales del navegador

### Resultados de Simulación

```powershell
# Create credential simulation results
$results = @{
    "VeeamCredentials" = "admin:VeeamBackup123!"
    "SQLCredentials" = "sa:SqlAdmin2023!"
    "DomainCredentials" = "administrator:DomainPass456!"
    "BrowserCredentials" = "user@company.com:WebPass789!"
}

Write-Host "Credential Harvesting Simulation Results:" -ForegroundColor Green
$results | ConvertTo-Json | Write-Host

Write-Host "Qilin credential harvesting simulation completed" -ForegroundColor Red
```
**Explicación línea por línea**:
- **Línea 2-7**: Crea hashtable con credenciales simuladas "robadas"
- **Línea 9**: Header para resultados
- **Línea 10**: Convierte a JSON y muestra las credenciales "robadas"
- **Línea 12**: Confirma finalización del harvesting

**Propósito del Script**: Simula de forma segura las técnicas específicas de robo de credenciales que Qilin utiliza, focalizándose en objetivos de alto valor.

---

## Flujo de Ejecución Completo

### 1. Inicialización del Test
```
main() → test() → Dropper initialization → Component quarantine checks
```

### 2. Fase 1: Verificación WSL
```
executeQilinSimulation() → checkWSLInstallation() → installWSL() (si necesario)
```

### 3. Fase 2: Ejecución Multiplataforma
```
executeLinuxPayload() → WSL bash execution → Linux reconnaissance
```

### 4. Fase 3: Harvesting de Credenciales
```
harvestCredentials() → PowerShell credential theft simulation
```

### 5. Fase 4: Ataque BYOVD
```
byovdAttack() → Driver loading → Privilege escalation simulation
```

### 6. Fase 5: Movimiento Lateral
```
lateralMovement() → Network reconnaissance → SSH attempts
```

### 7. Evaluación de Resultados
```
Phase completion tracking → Success/Failure determination → EDR evaluation
```

---

## Técnicas de Evasión Implementadas

### 1. **Cross-Platform Execution Evasion**
- **Técnica**: Usar WSL para ejecutar binarios Linux
- **Evasión**: EDRs enfocados en Windows pueden no monitorear WSL
- **Implementación**: `wsl bash script.sh`

### 2. **Living-Off-The-Land**
- **Técnica**: Usar herramientas legítimas del sistema
- **Evasión**: Herramientas firmadas y confiables
- **Implementación**: `sc.exe`, `powershell.exe`, `wsl.exe`

### 3. **Indirect Command Execution**
- **Técnica**: Ejecutar comandos a través de intérpretes
- **Evasión**: Ofusca la intención real del comando
- **Implementación**: PowerShell con `-ExecutionPolicy Bypass`

### 4. **Binary Embedding**
- **Técnica**: Embeber payloads en el binario principal
- **Evasión**: Evita detección de archivos externos
- **Implementación**: `//go:embed` directives

### 5. **Driver Abuse**
- **Técnica**: Cargar drivers vulnerables firmados
- **Evasión**: Bypass de controles de integridad
- **Implementación**: Service creation con driver vulnerable

### 6. **Credential Targeting**
- **Técnica**: Buscar credenciales en ubicaciones específicas
- **Evasión**: Imita acceso legítimo a configuraciones
- **Implementación**: Registry queries y file system searches

---

## Conclusión Técnica

Este test implementa una simulación realista y completa de las técnicas avanzadas de Qilin ransomware, específicamente su innovadora aproximación multiplataforma. La implementación detallada línea por línea demuestra:

1. **Realismo Técnico**: Cada función simula comportamientos auténticos de malware
2. **Evasión Sofisticada**: Múltiples técnicas para evitar detección EDR
3. **Cobertura Completa**: Desde instalación hasta exfiltración de credenciales
4. **Seguridad en Testing**: Simulación sin daño real al sistema
5. **Educación en Seguridad**: Código claro y bien documentado para aprendizaje

El test logra su objetivo de evaluar la capacidad de detección de sistemas de seguridad contra amenazas emergentes que utilizan enfoques multiplataforma para evadir defensas tradicionales.