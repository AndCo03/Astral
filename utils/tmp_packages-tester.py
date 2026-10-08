from ssh import SSHSession          # il tuo file SSH
from packages import PackageManager # il tuo file PackageManager

# 1) Connessione
ssh = SSHSession(
    host="192.168.1.20",
    username="server-admin",
    password="admin",     # oppure key_filename="/home/me/.ssh/id_rsa"
)
ssh.connect()
ssh.set_sudo_password("admin")   # se sudo richiede password

try:
    pm = PackageManager(ssh)

    # 2) Rileva OS
    print("OS:", pm.detect_os())

    # 3) Aggiorna cache
    pm.update_cache()

    # 4) Verifica se un pacchetto è già presente
    print("htop installato prima?:", pm.is_installed("htop"))

    # 5) Installa (scegli un pacchetto innocuo per il test)
    installed = pm.install(["htop"])
    print("Installati:", installed)

    # 6) Verifica post-installazione
    print("htop installato dopo?:", pm.is_installed("htop"))

    # 7) Cleanup
    pm.cleanup()
    print("htop installato dopo cleanup?:", pm.is_installed("htop"))

finally:
    ssh.close()