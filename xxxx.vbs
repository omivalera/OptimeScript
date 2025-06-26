Set UAC = CreateObject("Shell.Application")
UAC.ShellExecute "python.exe", """E:\EACM\Escritorio\Nueva carpeta\yasta.py""", "", "runas", 1
