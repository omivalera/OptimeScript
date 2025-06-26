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

def run_command(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        print(f"[CMD] {command}")
        print(result.stdout)
        if result.stderr:
            print("[ERROR]", result.stderr)
    except Exception as e:
        print("[EXCEPTION]", str(e))

def optimize():
    print("\n=== INICIANDO OPTIMIZACIÓN PARA GAMING ===")
    run_command('powercfg /setactive SCHEME_MIN')

    services = ['SysMain', 'WSearch', 'DiagTrack', 'wuauserv']
    for svc in services:
        run_command(f'sc stop {svc}')
        run_command(f'sc config {svc} start= demand')

    run_command('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f')
    run_command('reg add "HKCU\\System\\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f')
    run_command('reg add "HKCU\\Control Panel\\Desktop\\WindowMetrics" /v MinAnimate /t REG_SZ /d 0 /f')

    for proc in ['OneDrive', 'Cortana', 'msedge']:
        run_command(f'taskkill /f /im {proc}.exe')

    print("=== OPTIMIZACIÓN COMPLETA ===\n")

def restore():
    print("\n=== RESTAURANDO CONFIGURACIÓN ORIGINAL ===")
    run_command('powercfg /setactive SCHEME_BALANCED')

    services = ['SysMain', 'WSearch', 'DiagTrack', 'wuauserv']
    for svc in services:
        run_command(f'sc config {svc} start= auto')
        run_command(f'sc start {svc}')

    run_command('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 1 /f')
    run_command('reg add "HKCU\\System\\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 1 /f')
    run_command('reg add "HKCU\\Control Panel\\Desktop\\WindowMetrics" /v MinAnimate /t REG_SZ /d 1 /f')

    print("=== RESTAURACIÓN COMPLETA ===\n")

def build_gui():
    root = tk.Tk()
    root.title("Windows Gaming Optimizer")
    root.geometry("300x200")

    tk.Button(root, text="Optimizar para Gaming", command=optimize, height=2, width=25).pack(pady=10)
    tk.Button(root, text="Restaurar Configuración", command=restore, height=2, width=25).pack(pady=10)
    tk.Button(root, text="Salir", command=root.destroy, height=1, width=15).pack(pady=20)

    root.mainloop()

if __name__ == "__main__":
    if not is_windows():
        print("Este script solo funciona en Windows.")
        sys.exit()

    if not is_admin():
        # Re-ejecuta como administrador
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, ' '.join(sys.argv), None, 1)
        sys.exit()

    build_gui()
