import requests
import re
import time
import base64
import os
import sys
import subprocess
import threading
import itertools
import urllib3
from colorama import Fore, Style, init

# Inicializações
# Desativa avisos de certificado HTTPS inseguros
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

# Padrões regex. Detectar dados sensiveis
# Gerador -> https://regex-generator.olafneumann.org
PATTERNS = {
    r'(https?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+)': "URLs",
    r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+': "Emails",
    r'\b((?:\d{1,3}\.){3}\d{1,3})\b': "IPv4 Addresses",
    r'\b([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b': "IPv6 Addresses",
    r'[a-zA-Z0-9+/=]{10,}==?': "Base64 Encoded Data",
}

def base64_decoder(data):
    """Decodifica uma string Base64."""
    try:
        if len(data) % 4 == 0:
            return base64.b64decode(data).decode('utf-8', errors='ignore')
    except Exception as error:
        return f"Erro ao decodificar Base64: {error}"
    return "Dados Base64 inválidos"

def list_commits():
    """Lista commits de um repositório git."""
    print(f"{Fore.LIGHTCYAN_EX}[>] Listando commits...")
    process = subprocess.run(['git', 'log', '--pretty=format:%H - %an: %s'], capture_output=True, text=True)
    if process.returncode == 0:
        print(f"{Fore.LIGHTGREEN_EX}{process.stdout}")
    else:
        print(f"{Fore.RED}[!] Falha ao listar commits.")

def view_commit(commit_hash):
    """Visualiza um commit específico pelo hash."""
    print(f"{Fore.LIGHTCYAN_EX}[>] Visualizando commit: {commit_hash}")
    process = subprocess.run(['git', 'show', commit_hash], capture_output=True, text=True)
    if process.returncode == 0:
        print(f"{Fore.LIGHTGREEN_EX}{process.stdout}")
    else:
        print(f"{Fore.RED}[!] Falha ao exibir commit: {commit_hash}")

def analyze_git_exposure(url):
    """Verifica se o diretório .git está exposto no alvo."""
    paths = [
        ".git/HEAD", ".git/config", ".git/COMMIT_EDITMSG", ".git/logs/HEAD",
        ".git/logs/refs/heads/master", ".git/logs/refs/remotes/origin/master",
        ".git/info/exclude", ".git/refs/remotes/origin/master"
    ]
    data_found = {name: set() for name in PATTERNS.values()}
    exposed = False

    for path in paths:
        target = f"{url}/{path}"
        response = requests.get(target, verify=False)

        if response.status_code == 200 and not any(tag in response.text.lower() for tag in ["<html", "<body", "<title", "<head"]):
            exposed = True
            print(f"{Fore.LIGHTGREEN_EX}[+] Caminho encontrado: {target}")

            for pattern, name in PATTERNS.items():
                matches = re.findall(pattern, response.text)
                for match in matches:
                    data_found[name].add(match)

    # Imprime dados sensíveis encontrados
    for name, matches in data_found.items():
        if matches:
            print(f"{Fore.RED}[!] {name}:")
            for match in matches:
                print(f"{Fore.LIGHTBLUE_EX}    [-] {match}")
                if name == "Base64 Encoded Data":
                    decoded = base64_decoder(match)
                    print(f"{Fore.LIGHTYELLOW_EX}    [>] Decodificado: {decoded}")

    if exposed:
        download_git_dir(url)
    else:
        print(f"{Fore.LIGHTYELLOW_EX}[>] Nenhum repositório Git exposto encontrado.")
    
    print(f"{Fore.LIGHTCYAN_EX}[>] Verificação concluída.")
    return exposed

def spinner():
    """Exibe um spinner enquanto um processo está em execução."""
    for char in itertools.cycle(['[|]', '[/]', '[-]', '[\\]']):
        if stop_spinner:
            break
        print(f"\r{Fore.LIGHTGREEN_EX}[+] Baixando {char}", end="")
        time.sleep(0.1)
    print(f"\r{Fore.LIGHTGREEN_EX}[+] Download concluído!")

def download_git_dir(url):
    """Baixa o diretório .git."""
    global stop_spinner
    stop_spinner = False

    option = input(f"{Fore.LIGHTCYAN_EX}[>] Deseja baixar o diretório '.git'? (s/n): ").lower()
    if option == 's':
        print(f"{Fore.LIGHTGREEN_EX}[+] Iniciando download do diretório .git...")
        thread = threading.Thread(target=spinner)
        thread.start()

        os.system(f"wget --mirror --no-check-certificate -I .git -P ./git_download {url}/.git/ --quiet")

        stop_spinner = True
        thread.join()

        site_name = url.split("//")[1].split("/")[0]
        os.chdir(f'./git_download/{site_name}')
        verify_git_status()
    else:
        print(f"{Fore.LIGHTGREEN_EX}[+] Saindo...")
        time.sleep(2)
        sys.exit(0)

def verify_git_status():
    """Verifica o status do repositório git."""
    try:
        status = subprocess.run(['git', 'status'], capture_output=True, text=True, check=True)

        if "deleted" in status.stdout:
            print(status.stdout)
            option = input(f"{Fore.LIGHTCYAN_EX}[>] Deseja restaurar arquivos deletados? (s/n): ").lower()
            if option == 's':
                subprocess.run(['git', 'restore', '.'])
                print(f"{Fore.LIGHTGREEN_EX}[+] Arquivos restaurados com sucesso.")

    except subprocess.CalledProcessError as error:
        if "unknown index entry" in error.stderr or "is corrupt" in error.stderr:
            handle_corrupt_repo()

def handle_corrupt_repo():
    """Lida com repositórios git corrompidos."""
    print(f"{Fore.LIGHTRED_EX}[!] Corrupção detectada no repositório Git. Tentando reparar...")
    time.sleep(4)
    integrity_check = subprocess.run(['git', 'fsck'], capture_output=True, text=True)
    
    if integrity_check.returncode != 0:
        print(f"{Fore.LIGHTRED_EX}[!] Verificação de integridade do Git falhou.")
    else:
        print(f"{Fore.LIGHTYELLOW_EX}[>] Verificação de integridade concluída. Corrigindo objetos corrompidos...")
        print(f"{Fore.LIGHTCYAN_EX}[>] Recomenda-se limpar o repositório manualmente ou usar: 'git gc --prune=now'")

    # Remover índice corrompido e resetar
    try:
        subprocess.run(['rm', '-f', '.git/index'], check=True)
        subprocess.run(['git', 'reset'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        verify_git_status()
    except subprocess.CalledProcessError:
        print(f"{Fore.LIGHTRED_EX}[!] Falha ao resetar índice Git.")
        sys.exit(0)

def main():
    if os.geteuid() != 0:
        print("\033[91m[!] Este script deve ser executado como root!\033[0m")
        sys.exit(1)

    target = input("Digite a URL de destino: ")
    start_time = time.time()
    if analyze_git_exposure(target):
        while True:
            option = input(f"{Fore.LIGHTCYAN_EX}[>] Deseja listar ou visualizar um commit específico? (listar/visualizar/sair): ").lower()
            if option == 'listar':
                list_commits()
            elif option == 'visualizar':
                commit_hash = input(f"{Fore.LIGHTCYAN_EX}[>] Insira o hash do commit: ")
                view_commit(commit_hash)
            elif option == 'sair':
                print(f"{Fore.LIGHTGREEN_EX}[+] Saindo...")
                break
            else:
                print(f"{Fore.RED}[!] Opção inválida. Escolha 'listar', 'visualizar' ou 'sair'.")
    else:
        print(f"{Fore.LIGHTGREEN_EX}[+] Saindo...")

if __name__ == "__main__":
    main()

