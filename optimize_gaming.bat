@echo off
:: Ejecuta el script Python como administrador
powershell -Command "Start-Process python -ArgumentList 'E:\EACM\Escritorio\Nueva carpeta\yasta.py' -Verb RunAs"
pause
