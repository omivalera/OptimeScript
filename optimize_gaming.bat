@echo off
:: Verifica si se ejecuta como administrador
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Este script requiere permisos de administrador. Relanzando...
    powershell -Command "Start-Process cmd -ArgumentList '/c %~f0' -Verb RunAs"
    exit /b
)

:: Ejecuta el script Python
python "E:\EACM\Escritorio\Nueva carpeta\yasta.py"
if %errorLevel% neq 0 (
    echo Error al ejecutar el script Python. Revisa el mensaje de error arriba.
    pause
    exit /b
)

pause