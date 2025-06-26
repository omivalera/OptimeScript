import tkinter as tk
import subprocess
import os
import sys
import ctypes
import platform

def is_windows():
    return platform.system().lower() == "windows"

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def is_service_running(service_name):
    try:
        result = subprocess.run(f'sc query {service_name}', shell=True, capture_output=True, text=True)
        return "RUNNING" in result.stdout
    except:
        return False

def is_process_running(process_name):
    try:
        result = subprocess.run(f'tasklist /FI "IMAGENAME eq {process_name}"', shell=True, capture_output=True, text=True)
        return process_name.lower() in result.stdout.lower()
    except:
        return False

def run_command(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        output = f"[CMD] {command}\n{result.stdout}"
        if result.stderr:
            output += f"\n[ERROR] {result.stderr}"
        print(output)
        return True
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Fallo al ejecutar {command}: {e}")
        return False
    except Exception as e:
        print(f"[EXCEPTION] Error inesperado en {command}: {str(e)}")
        return False

def clean_temp_files():
    print("\n=== LIMPIANDO ARCHIVOS TEMPORALES ===")
    temp_dirs = ['%temp%\\*', 'C:\\Windows\\Temp\\*']
    for temp_dir in temp_dirs:
        try:
            result = subprocess.run(f'del /q /f /s "{temp_dir}"', shell=True, capture_output=True, text=True)
            print(f"[CMD] del /q /f /s \"{temp_dir}\"")
            if result.stdout:
                print(result.stdout)
            if result.stderr:
                print(f"[ERROR] Algunos archivos no se pudieron eliminar: {result.stderr}")
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Fallo al limpiar {temp_dir}: {e}")
        except Exception as e:
            print(f"[EXCEPTION] Error inesperado al limpiar {temp_dir}: {str(e)}")
    print("=== LIMPIEZA COMPLETA ===\n")

def optimize():
    print("\n=== INICIANDO OPTIMIZACIÓN PARA GAMING ===")
    run_command('powercfg /setactive SCHEME_MIN')
    run_command('powercfg /change standby-timeout-ac 0')
    run_command('powercfg /change hibernate-timeout-ac 0')
    run_command('powercfg /change disk-timeout-ac 0')

    services = ['SysMain', 'WSearch', 'DiagTrack', 'wuauserv', 'XboxGipSvc', 'MapsBroker']
    for svc in services:
        if is_service_running(svc):
            run_command(f'sc stop {svc}')
        else:
            print(f"[INFO] El servicio {svc} no está en ejecución.")
        run_command(f'sc config {svc} start= demand')

    run_command('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f')
    run_command('reg add "HKCU\\System\\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f')
    run_command('reg add "HKCU\\Control Panel\\Desktop\\WindowMetrics" /v MinAnimate /t REG_SZ /d 0 /f')
    run_command('reg add "HKCU\\Software\\Microsoft\\GameBar" /v AllowAutoGameMode /t REG_DWORD /d 0 /f')
    run_command('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\PriorityControl" /v Win32PrioritySeparation /t REG_DWORD /d 38 /f')
    run_command('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\PushNotifications" /v ToastEnabled /t REG_DWORD /d 0 /f')
    run_command('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 2 /f')
    run_command('reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DriverSearching" /v SearchOrderConfig /t REG_DWORD /d 0 /f')
    run_command('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\BackgroundApps" /v GlobalUserDisabled /t REG_DWORD /d 1 /f')
    run_command('netsh int tcp set global autotuninglevel=disabled')
    run_command('netsh int tcp set global rss=enabled')
    run_command('fsutil behavior set disablelastaccess 1')

    processes = ['OneDrive.exe', 'Cortana.exe', 'msedge.exe']
    for proc in processes:
        if is_process_running(proc):
            run_command(f'taskkill /f /im {proc}')
        else:
            print(f"[INFO] El proceso {proc} no está en ejecución.")

    clean_temp_files()
    print("=== OPTIMIZACIÓN COMPLETA ===\n")

def restore():
    print("\n=== RESTAURANDO CONFIGURACIÓN ORIGINAL ===")
    run_command('powercfg /setactive SCHEME_BALANCED')
    run_command('powercfg /change standby-timeout-ac 15')
    run_command('powercfg /change hibernate-timeout-ac 30')
    run_command('powercfg /change disk-timeout-ac 20')

    services = ['SysMain', 'WSearch', 'DiagTrack', 'wuauserv', 'XboxGipSvc', 'MapsBroker']
    for svc in services:
        run_command(f'sc config {svc} start= auto')
        run_command(f'sc start {svc}')

    run_command('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 1 /f')
    run_command('reg add "HKCU\\System\\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 1 /f')
    run_command('reg add "HKCU\\Control Panel\\Desktop\\WindowMetrics" /v MinAnimate /t REG_SZ /d 1 /f')
    run_command('reg add "HKCU\\Software\\Microsoft\\GameBar" /v AllowAutoGameMode /t REG_DWORD /d 1 /f')
    run_command('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\PriorityControl" /v Win32PrioritySeparation /t REG_DWORD /d 2 /f')
    run_command('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\PushNotifications" /v ToastEnabled /t REG_DWORD /d 1 /f')
    run_command('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 0 /f')
    run_command('reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DriverSearching" /v SearchOrderConfig /t REG_DWORD /d 1 /f')
    run_command('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\BackgroundApps" /v GlobalUserDisabled /t REG_DWORD /d 0 /f')
    run_command('netsh int tcp set global autotuninglevel=normal')
    run_command('netsh int tcp set global rss=disabled')
    run_command('fsutil behavior set disablelastaccess 0')

    if not is_process_running('OneDrive.exe'):
        run_command('start "" "%LocalAppData%\\Microsoft\\OneDrive\\OneDrive.exe"')

    print("=== RESTAURACIÓN COMPLETA ===\n")

def build_gui():
    try:
        root = tk.Tk()
        root.title("Windows Gaming Optimizer")
        root.geometry("400x300")

        output_text = tk.Text(root, height=10, width=40)
        output_text.pack(pady=10)

        class StdoutRedirector:
            def __init__(self, text_widget):
                self.text_widget = text_widget

            def write(self, message):
                self.text_widget.insert(tk.END, message)
                self.text_widget.see(tk.END)
                sys.__stdout__.write(message)

            def flush(self):
                pass

        sys.stdout = StdoutRedirector(output_text)

        tk.Button(root, text="Optimizar para Gaming", command=optimize, height=2, width=25).pack(pady=10)
        tk.Button(root, text="Restaurar Configuración", command=restore, height=2, width=25).pack(pady=10)
        tk.Button(root, text="Salir", command=root.destroy, height=1, width=15).pack(pady=20)

        root.mainloop()
    except Exception as e:
        print(f"[ERROR] Fallo al crear la interfaz de Tkinter: {str(e)}")
        input("Presiona cualquier tecla para salir...")
        sys.exit(1)

if __name__ == "__main__":
    try:
        if not is_windows():
            print("Este script solo funciona en Windows.")
            input("Presiona cualquier tecla para salir...")
            sys.exit(1)

        if not is_admin():
            print("Este script requiere permisos de administrador. Relanzando...")
            input("Presiona cualquier tecla para continuar...")
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, ' '.join(sys.argv), None, 1)
            sys.exit(0)

        build_gui()
    except Exception as e:
        print(f"[ERROR GENERAL] Ocurrió un error: {str(e)}")
        input("Presiona cualquier tecla para salir...")
        sys.exit(1)