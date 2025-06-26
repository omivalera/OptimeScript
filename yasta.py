import tkinter as tk
import subprocess
import os
import sys
import ctypes
import platform
import time

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

def check_registry_value(key, value_name, expected_value):
    try:
        result = subprocess.run(f'reg query "{key}" /v {value_name}', shell=True, capture_output=True, text=True)
        if f"0x{expected_value:x}" in result.stdout or f"{expected_value}" in result.stdout:
            print(f"[INFO] {key}\\{value_name} ya está configurado como {expected_value}.")
            return True
        return False
    except:
        return False

def stop_service_with_timeout(service_name, timeout_seconds=5):
    if is_service_running(service_name):
        print(f"[INFO] Intentando detener el servicio {service_name}...")
        run_command(f'sc stop {service_name}')
        start_time = time.time()
        while is_service_running(service_name) and (time.time() - start_time) < timeout_seconds:
            time.sleep(1)
        if is_service_running(service_name):
            print(f"[WARNING] El servicio {service_name} no se detuvo completamente (estado STOP_PENDING). Esto puede no afectar el rendimiento.")
        else:
            print(f"[INFO] El servicio {service_name} se detuvo correctamente.")
    else:
        print(f"[INFO] El servicio {service_name} no está en ejecución.")

def configure_service(service_name):
    result = subprocess.run(f'sc qc {service_name}', shell=True, capture_output=True, text=True)
    if 'START_TYPE  : 3   DEMAND_START' in result.stdout:
        print(f"[INFO] El servicio {service_name} ya está configurado como inicio bajo demanda.")
        return
    run_command(f'sc config {service_name} start= demand')

def clean_temp_files():
    print("\n=== LIMPIANDO ARCHIVOS TEMPORALES ===")
    print("[INFO] Cierra todas las aplicaciones innecesarias para maximizar la limpieza de archivos temporales.")
    temp_dirs = ['%temp%\\*', 'C:\\Windows\\Temp\\*']
    for temp_dir in temp_dirs:
        try:
            result = subprocess.run(f'dir "{temp_dir}" /a:-d /s /b', shell=True, capture_output=True, text=True)
            files = result.stdout.splitlines()
            total_files = len(files)
            deleted_files = 0
            print(f"[INFO] Encontrados {total_files} archivos en {temp_dir}")
            result = subprocess.run(f'del /q /f /s "{temp_dir}"', shell=True, capture_output=True, text=True)
            print(f"[CMD] del /q /f /s \"{temp_dir}\"")
            if result.stdout:
                deleted_files = result.stdout.count('\n')
                print(result.stdout)
            if result.stderr:
                print(f"[ERROR] Algunos archivos no se pudieron eliminar: {result.stderr}")
            print(f"[INFO] Eliminados {deleted_files} de {total_files} archivos en {temp_dir}")
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Fallo al limpiar {temp_dir}: {e}")
        except Exception as e:
            print(f"[EXCEPTION] Error inesperado al limpiar {temp_dir}: {str(e)}")
    print("=== LIMPIEZA COMPLETA ===\n")

def check_system_status():
    print("\n=== VERIFICANDO ESTADO DEL SISTEMA ===")
    result = subprocess.run('powercfg /getactivescheme', shell=True, capture_output=True, text=True)
    print(f"[INFO] Plan de energía activo: {result.stdout}")
    result = subprocess.run('wmic memorychip get speed', shell=True, capture_output=True, text=True)
    print(f"[INFO] Velocidad de la RAM: {result.stdout}")
    try:
        result = subprocess.run('dxdiag /t dxdiag.txt', shell=True, capture_output=True, text=True)
        with open('dxdiag.txt', 'r') as f:
            for line in f:
                if 'Dedicated Video Memory' in line or 'Shared System Memory' in line:
                    print(f"[INFO] {line.strip()}")
        os.remove('dxdiag.txt')
    except Exception as e:
        print(f"[ERROR] No se pudo verificar la VRAM: {str(e)}")
    services = ['SysMain', 'WSearch', 'DiagTrack', 'wuauserv', 'XboxGipSvc', 'MapsBroker', 'DPS', 'WdiSystemHost', 'WpnService', 'DoSvc']
    for svc in services:
        if is_service_running(svc):
            print(f"[INFO] El servicio {svc} está en ejecución.")
        else:
            print(f"[INFO] El servicio {svc} no está en ejecución.")
    print("=== VERIFICACIÓN COMPLETA ===\n")

def optimize():
    print("\n=== INICIANDO OPTIMIZACIÓN PARA GAMING ===")
    # Verificar plan de energía
    result = subprocess.run('powercfg /getactivescheme', shell=True, capture_output=True, text=True)
    if "SCHEME_MIN" not in result.stdout:
        run_command('powercfg /setacvalueindex SCHEME_MIN 54533251-82be-4824-96c1-47b60b740d00 be337238-0d82-4146-a960-4f3749d470c7 1')
        run_command('powercfg /setactive SCHEME_MIN')
    else:
        print("[INFO] Plan de energía ya configurado como Alto Rendimiento.")
    run_command('powercfg /change standby-timeout-ac 0')
    run_command('powercfg /change hibernate-timeout-ac 0')
    run_command('powercfg /change disk-timeout-ac 0')

    services = ['SysMain', 'WSearch', 'DiagTrack', 'wuauserv', 'XboxGipSvc', 'MapsBroker', 'DPS', 'WdiSystemHost', 'WpnService', 'DoSvc']
    for svc in services:
        stop_service_with_timeout(svc)
        configure_service(svc)

    # Aplicar cambios en el registro solo si no están configurados
    if not check_registry_value("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\GameDVR", "AppCaptureEnabled", 0):
        run_command('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f')
    if not check_registry_value("HKCU\\System\\GameConfigStore", "GameDVR_Enabled", 0):
        run_command('reg add "HKCU\\System\\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f')
    if not check_registry_value("HKCU\\Control Panel\\Desktop\\WindowMetrics", "MinAnimate", 0):
        run_command('reg add "HKCU\\Control Panel\\Desktop\\WindowMetrics" /v MinAnimate /t REG_SZ /d 0 /f')
    if not check_registry_value("HKCU\\Software\\Microsoft\\GameBar", "AllowAutoGameMode", 0):
        run_command('reg add "HKCU\\Software\\Microsoft\\GameBar" /v AllowAutoGameMode /t REG_DWORD /d 0 /f')
    if not check_registry_value("HKCU\\Software\\Microsoft\\GameBar", "UseNexusForGameBarEnabled", 0):
        run_command('reg add "HKCU\\Software\\Microsoft\\GameBar" /v UseNexusForGameBarEnabled /t REG_DWORD /d 0 /f')
    if not check_registry_value("HKLM\\SYSTEM\\CurrentControlSet\\Control\\PriorityControl", "Win32PrioritySeparation", 38):
        run_command('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\PriorityControl" /v Win32PrioritySeparation /t REG_DWORD /d 38 /f')
    if not check_registry_value("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\PushNotifications", "ToastEnabled", 0):
        run_command('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\PushNotifications" /v ToastEnabled /t REG_DWORD /d 0 /f')
    if not check_registry_value("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects", "VisualFXSetting", 2):
        run_command('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 2 /f')
    if not check_registry_value("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DriverSearching", "SearchOrderConfig", 0):
        run_command('reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DriverSearching" /v SearchOrderConfig /t REG_DWORD /d 0 /f')
    if not check_registry_value("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\BackgroundApps", "GlobalUserDisabled", 1):
        run_command('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\BackgroundApps" /v GlobalUserDisabled /t REG_DWORD /d 1 /f')
    if not check_registry_value("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile", "NetworkThrottlingIndex", 0xffffffff):
        run_command('reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 0xffffffff /f')
    if not check_registry_value("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games", "GPU Priority", 8):
        run_command('reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f')
    if not check_registry_value("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games", "Priority", 6):
        run_command('reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games" /v "Priority" /t REG_DWORD /d 6 /f')
    if not check_registry_value("HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers", "HwSchMode", 2):
        run_command('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers" /v HwSchMode /t REG_DWORD /d 2 /f')
    run_command('bcdedit /set disabledynamictick yes')
    run_command('bcdedit /set useplatformclock no')
    run_command('fsutil behavior set disablelastaccess 1')
    if not check_registry_value("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management", "FeatureSettingsOverride", 3):
        run_command('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 3 /f')
    if not check_registry_value("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management", "FeatureSettingsOverrideMask", 3):
        run_command('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f')

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

    services = ['SysMain', 'WSearch', 'DiagTrack', 'wuauserv', 'XboxGipSvc', 'MapsBroker', 'DPS', 'WdiSystemHost', 'WpnService', 'DoSvc']
    for svc in services:
        run_command(f'sc config {svc} start= auto')
        run_command(f'sc start {svc}')

    run_command('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 1 /f')
    run_command('reg add "HKCU\\System\\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 1 /f')
    run_command('reg add "HKCU\\Control Panel\\Desktop\\WindowMetrics" /v MinAnimate /t REG_SZ /d 1 /f')
    run_command('reg add "HKCU\\Software\\Microsoft\\GameBar" /v AllowAutoGameMode /t REG_DWORD /d 1 /f')
    run_command('reg add "HKCU\\Software\\Microsoft\\GameBar" /v UseNexusForGameBarEnabled /t REG_DWORD /d 1 /f')
    run_command('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\PriorityControl" /v Win32PrioritySeparation /t REG_DWORD /d 2 /f')
    run_command('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\PushNotifications" /v ToastEnabled /t REG_DWORD /d 1 /f')
    run_command('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 0 /f')
    run_command('reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DriverSearching" /v SearchOrderConfig /t REG_DWORD /d 1 /f')
    run_command('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\BackgroundApps" /v GlobalUserDisabled /t REG_DWORD /d 0 /f')
    run_command('reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 0xa /f')
    run_command('reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games" /v "GPU Priority" /t REG_DWORD /d 0 /f')
    run_command('reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games" /v "Priority" /t REG_DWORD /d 0 /f')
    run_command('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers" /v HwSchMode /t REG_DWORD /d 1 /f')
    run_command('bcdedit /set disabledynamictick no')
    run_command('bcdedit /set useplatformclock yes')
    run_command('fsutil behavior set disablelastaccess 0')
    run_command('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 0 /f')
    run_command('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 0 /f')

    if not is_process_running('OneDrive.exe'):
        run_command('start "" "%LocalAppData%\\Microsoft\\OneDrive\\OneDrive.exe"')

    print("=== RESTAURACIÓN COMPLETA ===\n")

def build_gui():
    try:
        root = tk.Tk()
        root.title("Windows Gaming Optimizer - Ryzen 3 2200G")
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
        tk.Button(root, text="Verificar Estado", command=check_system_status, height=2, width=25).pack(pady=10)
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