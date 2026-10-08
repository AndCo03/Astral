from ssh import SSHSession

def main():
    host = "192.168.1.20"  # o "localhost"
    port = 22
    username = "server-admin"
    password = "admin"
    # oppure key_filename="C:/Users/.../.ssh/id_rsa"

    session = SSHSession(host, port, username, password=password)
    try:
        session.connect()
        print("Connessione riuscita.")
        stdout, stderr, code = session.execute("whoami")
        print("STDOUT:", stdout)
        print("STDERR:", stderr)
        print("Exit code:", code)

        # Test sudo (se l'utente ha sudo)
        # session.set_sudo_password(password)
        # stdout, stderr, code = session.execute("whoami", sudo=True)
        # print("Sudo STDOUT:", stdout)
        # print("Sudo STDERR:", stderr)
        # print("Sudo exit code:", code)

    except Exception as e:
        print("Errore:", e)
    finally:
        session.close()

if __name__ == "__main__":
    main()