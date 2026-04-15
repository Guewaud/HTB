#!/usr/bin/env python3
"""
HTB Automation Script
Automatisatoin de  la reconnaissance dans CherryTree
"""

import os
import sys
import shutil
import subprocess
import sqlite3
import glob
import re
import xml.etree.ElementTree as ET
from datetime import datetime

# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────
CHERRYTREE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Cherrytree")
TEMPLATE_FILE  = os.path.join(CHERRYTREE_DIR, "PenTest Template.ctb")
HOSTS_FILE     = "/etc/hosts"

# ─────────────────────────────────────────────
# COULEURS TERMINAL
# ─────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def banner():
    print(f"""{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════╗
║         HTB  Automation - CherryTree 	           ║
║                   by htb-script                  ║
╚══════════════════════════════════════════════════╝{C.RESET}
""")

def info(msg):    print(f"{C.BLUE}[*]{C.RESET} {msg}")
def success(msg): print(f"{C.GREEN}[+]{C.RESET} {msg}")
def warn(msg):    print(f"{C.YELLOW}[!]{C.RESET} {msg}")
def error(msg):   print(f"{C.RED}[-]{C.RESET} {msg}")

# ─────────────────────────────────────────────
# GESTION CHERRYTREE (.ctb = SQLite)
# ─────────────────────────────────────────────

def list_ctb_files():
    """Liste tous les fichiers .ctb dans le dossier CherryTree sauf le template."""
    files = glob.glob(os.path.join(CHERRYTREE_DIR, "*.ctb"))
    return [f for f in files if "PenTest Template" not in os.path.basename(f)]


def get_node_id(conn, name, parent_id=None):
    """Trouve l'ID d'un nœud par son nom, optionnellement sous un parent donné."""
    cur = conn.cursor()
    if parent_id is None:
        cur.execute("SELECT node_id FROM node WHERE name = ?", (name,))
    else:
        # Cherche dans la table children pour trouver les enfants du parent
        cur.execute("""
            SELECT n.node_id FROM node n
            JOIN children c ON n.node_id = c.node_id
            WHERE n.name = ? AND c.father_id = ?
        """, (name, parent_id))
    row = cur.fetchone()
    return row[0] if row else None


def get_root_node_id(conn):
    """Retourne l'ID du nœud racine (Target 1) ou le premier nœud sans parent."""
    cur = conn.cursor()
    # Les nœuds sans parent ont father_id = 0 dans la table children
    cur.execute("""
        SELECT n.node_id, n.name FROM node n
        JOIN children c ON n.node_id = c.node_id
        WHERE c.father_id = 0
        ORDER BY c.sequence
    """)
    rows = cur.fetchall()
    if rows:
        return rows[0][0], rows[0][1]
    return None, None


def get_all_top_nodes(conn):
    """Retourne tous les nœuds racines."""
    cur = conn.cursor()
    cur.execute("""
        SELECT n.node_id, n.name FROM node n
        JOIN children c ON n.node_id = c.node_id
        WHERE c.father_id = 0
        ORDER BY c.sequence
    """)
    return cur.fetchall()


def get_children_names(conn, parent_id):
    """Retourne les noms des enfants d'un nœud."""
    cur = conn.cursor()
    cur.execute("""
        SELECT n.name, n.node_id FROM node n
        JOIN children c ON n.node_id = c.node_id
        WHERE c.father_id = ?
        ORDER BY c.sequence
    """, (parent_id,))
    return cur.fetchall()


def find_tcp_services_node(conn):
    """
    Cherche le nœud 'TCP Services' dans l'arbre :
    Target 1 → Enumeration → TCP Services
    """
    cur = conn.cursor()

    # Cherche tous les nœuds "TCP Services"
    cur.execute("SELECT node_id, name FROM node WHERE name LIKE '%TCP%'")
    candidates = cur.fetchall()

    if not candidates:
        # Recherche plus large
        cur.execute("SELECT node_id, name FROM node WHERE name LIKE '%TCP%' OR name = 'TCP Services'")
        candidates = cur.fetchall()

    if candidates:
        return candidates[0][0]  # Prend le premier trouvé

    return None


def get_node_content(conn, node_id):
    """Récupère le contenu XML d'un nœud."""
    cur = conn.cursor()
    cur.execute("SELECT txt FROM node WHERE node_id = ?", (node_id,))
    row = cur.fetchone()
    return row[0] if row else ""


def append_nmap_to_tcp_node(conn, node_id, ip, nmap_output):
    """Ajoute les résultats nmap au nœud TCP Services."""
    cur = conn.cursor()
    cur.execute("SELECT txt, syntax FROM node WHERE node_id = ?", (node_id,))
    row = cur.fetchone()

    if not row:
        error(f"Nœud {node_id} introuvable.")
        return

    current_txt, syntax = row
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if syntax == "plain-text" or not syntax:
        # Nœud texte simple
        separator = "\n" + "="*60 + "\n"
        header = f"[{timestamp}] NMAP SCAN - {ip}\n"
        new_content = (current_txt or "") + separator + header + nmap_output
        cur.execute("UPDATE node SET txt = ? WHERE node_id = ?", (new_content, node_id))
    else:
        # Nœud XML CherryTree (rich text)
        new_content = _append_to_rich_text(current_txt, timestamp, ip, nmap_output)
        cur.execute("UPDATE node SET txt = ? WHERE node_id = ?", (new_content, node_id))

    conn.commit()
    success("Résultats nmap intégrés dans TCP Services ✓")


def _append_to_rich_text(existing_xml, timestamp, ip, nmap_output):
    """Construit le XML CherryTree avec les résultats nmap."""
    # CherryTree stocke le contenu comme XML avec balise <node>
    header_text = f"\n{'='*60}\n[{timestamp}] NMAP SCAN — {ip}\n{'='*60}\n"
    full_text = header_text + nmap_output + "\n"

    try:
        if existing_xml and existing_xml.strip().startswith("<"):
            root = ET.fromstring(existing_xml)
            # Trouve le dernier élément texte et ajoute à la fin
            # CherryTree utilise des sous-éléments <rich_text>
            new_elem = ET.SubElement(root, "rich_text")
            new_elem.text = full_text
            return ET.tostring(root, encoding="unicode")
        else:
            # Crée un XML simple
            root = ET.Element("node")
            if existing_xml:
                existing = ET.SubElement(root, "rich_text")
                existing.text = existing_xml
            new_elem = ET.SubElement(root, "rich_text")
            new_elem.text = full_text
            return ET.tostring(root, encoding="unicode")
    except ET.ParseError:
        # Si l'XML est corrompu, on ajoute en mode texte
        return (existing_xml or "") + full_text


def rename_box_node(conn, box_name):
    """Renomme le premier nœud racine avec le nom de la box."""
    root_id, root_name = get_root_node_id(conn)
    if root_id:
        cur = conn.cursor()
        cur.execute("UPDATE node SET name = ? WHERE node_id = ?", (box_name, root_id))
        conn.commit()
        success(f"Nœud racine renommé en '{box_name}'")


# ─────────────────────────────────────────────
# CRÉATION / SÉLECTION DE BOX
# ─────────────────────────────────────────────

def select_existing_box():
    """Affiche la liste des boxes existantes et laisse l'utilisateur en choisir une."""
    files = list_ctb_files()
    if not files:
        warn("Aucune box trouvée dans le dossier CherryTree.")
        return None

    print(f"\n{C.BOLD}Boxes disponibles :{C.RESET}")
    for i, f in enumerate(files, 1):
        name = os.path.basename(f).replace(".ctb", "")
        print(f"  {C.CYAN}[{i}]{C.RESET} {name}")
    print(f"  {C.CYAN}[0]{C.RESET} Annuler")

    while True:
        try:
            choice = int(input(f"\n{C.BOLD}Choix >{C.RESET} ").strip())
            if choice == 0:
                return None
            if 1 <= choice <= len(files):
                return files[choice - 1]
            warn("Choix invalide.")
        except ValueError:
            warn("Entre un numéro valide.")


def create_new_box():
    """Crée un nouveau fichier .ctb basé sur le template."""
    if not os.path.exists(TEMPLATE_FILE):
        error(f"Template introuvable : {TEMPLATE_FILE}")
        error("Vérifie que 'PenTest Template.ctb' est bien dans Cherrytree/")
        sys.exit(1)

    box_name = input(f"\n{C.BOLD}Nom de la box >{C.RESET} ").strip()
    if not box_name:
        error("Le nom ne peut pas être vide.")
        return None, None

    safe_name = re.sub(r'[^\w\-_. ]', '_', box_name)
    dest = os.path.join(CHERRYTREE_DIR, f"{safe_name}.ctb")

    if os.path.exists(dest):
        warn(f"Le fichier '{dest}' existe déjà.")
        ow = input("Écraser ? [o/N] ").strip().lower()
        if ow != 'o':
            return None, None

    shutil.copy2(TEMPLATE_FILE, dest)
    success(f"Fichier créé : {dest}")

    # Renomme le nœud racine avec le nom de la box
    try:
        conn = sqlite3.connect(dest)
        rename_box_node(conn, box_name)
        conn.close()
    except Exception as e:
        warn(f"Impossible de renommer le nœud racine : {e}")

    return dest, box_name


def open_cherrytree(ctb_path):
    """Ouvre CherryTree avec le fichier spécifié."""
    info(f"Ouverture de CherryTree : {os.path.basename(ctb_path)}")
    try:
        subprocess.Popen(
            ["cherrytree", ctb_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        success("CherryTree lancé ✓")
    except FileNotFoundError:
        warn("Commande 'cherrytree' non trouvée. Ouvre le fichier manuellement.")


# ─────────────────────────────────────────────
# NMAP
# ─────────────────────────────────────────────

def validate_ip(ip):
    """Valide basiquement une adresse IP ou hostname."""
    # IP v4 basique ou hostname
    ip_pattern = re.compile(
        r'^(\d{1,3}\.){3}\d{1,3}$'
        r'|^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
    )
    return bool(ip_pattern.match(ip))


def run_nmap(ip):
    """Lance le scan nmap et retourne le résultat."""
    cmd = ["nmap", "-sV", "-sC", "-O", "-oN", "-", ip]
    info(f"Lancement : {' '.join(cmd)}")
    print(f"{C.YELLOW}(Cela peut prendre quelques minutes...){C.RESET}\n")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600
        )
        output = result.stdout
        if result.returncode != 0 and not output:
            error("Nmap a échoué.")
            error(result.stderr)
            return None

        print(f"\n{C.BOLD}─── Résultat nmap ───{C.RESET}")
        print(output)
        return output

    except subprocess.TimeoutExpired:
        error("Timeout : le scan nmap a pris trop de temps.")
        return None
    except FileNotFoundError:
        error("'nmap' n'est pas installé ou introuvable dans le PATH.")
        return None


def parse_open_ports(nmap_output):
    """Extrait les ports ouverts et services du résultat nmap."""
    ports = []
    port_pattern = re.compile(
        r'^(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$', re.MULTILINE
    )
    for m in port_pattern.finditer(nmap_output):
        ports.append({
            "port":     m.group(1),
            "proto":    m.group(2),
            "service":  m.group(3),
            "version":  (m.group(4) or "").strip()
        })
    return ports


def check_http_port(ports):
    """Vérifie si le port 80 ou 443 (HTTP/HTTPS) est ouvert."""
    http_ports = []
    for p in ports:
        if p["port"] in ("80", "443", "8080", "8443") and p["proto"] == "tcp":
            http_ports.append(p)
    return http_ports


def extract_hostnames_from_nmap(nmap_output):
    """
    Extrait TOUS les hostnames/URLs trouvés dans la sortie nmap.
    Retourne une liste de hostnames uniques (sans http  ni slash final).

    Sources inspectées (par ordre de priorité) :
      1. |_http-title: Did not follow redirect to http://xxx.htb/
      2. |_http-title: ... (titre contenant un .htb ou .local)
      3. http-redirect / Location: http://xxx.htb/
      4. commonName= (certificats SSL)
      5. Service Info: Host: xxx.htb
      6. Nmap scan report for xxx (si ce n'est pas une IP)
    """
    found = []

    def add(hostname):
        """Normalise et ajoute un hostname s'il n'est pas déjà dans la liste."""
        h = hostname.strip().rstrip("/").lower()
        # Ignore les IP pures et les entrées vides
        if h and not re.match(r'^\d+\.\d+\.\d+\.\d+$', h) and h not in found:
            found.append(h)

    # 1. http-title avec redirection → "Did not follow redirect to http://example.htb/"
    for m in re.finditer(
        r'http-title.*?redirect.*?https?://([\w\.\-]+)', nmap_output, re.IGNORECASE
    ):
        add(m.group(1))

    # 2. Toute URL http(s) dans la sortie nmap contenant un TLD .htb / .local / .lan / .box
    for m in re.finditer(
        r'https?://([\w\.\-]+\.(?:htb|local|lan|box|thm))', nmap_output, re.IGNORECASE
    ):
        add(m.group(1))

    # 3. Location: header dans les scripts nmap
    for m in re.finditer(
        r'Location:\s*https?://([\w\.\-]+)', nmap_output, re.IGNORECASE
    ):
        add(m.group(1))

    # 4. Certificats SSL — commonName
    for m in re.finditer(r'commonName=([\w\.\-]+)', nmap_output):
        add(m.group(1))

    # 5. Service Info: Host:
    for m in re.finditer(r'Service Info:.*?Host:\s*([\w\.\-]+)', nmap_output):
        add(m.group(1))

    # 6. "Nmap scan report for hostname (ip)" — hostname textuel seulement
    m = re.search(r'Nmap scan report for ([\w\.\-]+)', nmap_output)
    if m and not re.match(r'^\d+\.\d+\.\d+\.\d+$', m.group(1)):
        add(m.group(1))

    return found


def update_hosts_file(ip, hostnames, box_name):
    """
    Ajoute une ou plusieurs entrées dans /etc/hosts (nécessite sudo).
    hostnames : liste de strings, ex. ['cctv.htb', 'www.cctv.htb']
    """
    try:
        with open(HOSTS_FILE, "r") as f:
            current_content = f.read()
    except PermissionError:
        error(f"Permission refusée pour lire {HOSTS_FILE}")
        return
    except Exception as e:
        error(f"Impossible de lire {HOSTS_FILE} : {e}")
        return

    # Filtre les hostnames déjà présents pour cette IP
    new_hostnames = []
    for h in hostnames:
        if h in current_content:
            warn(f"'{h}' déjà présent dans {HOSTS_FILE} — ignoré.")
        else:
            new_hostnames.append(h)

    if not new_hostnames:
        info("Aucune nouvelle entrée à ajouter dans /etc/hosts.")
        return

    # Construit la ligne : "IP.IP.IP.IP    example.htb www.example.htb    # HTB - exemple"
    hosts_part = "\t".join(new_hostnames)
    full_line = f"{ip}\t{hosts_part}\t# HTB - {box_name}"

    info(f"Ligne à ajouter dans {HOSTS_FILE} :")
    print(f"  {C.CYAN}{full_line}{C.RESET}")
    print(f"{C.YELLOW}(Mot de passe sudo requis){C.RESET}")

    cmd = f"echo '{full_line}' | sudo tee -a {HOSTS_FILE} > /dev/null"
    result = subprocess.run(cmd, shell=True)

    if result.returncode == 0:
        success(f"/etc/hosts mis à jour ✓ → {full_line}")
    else:
        error("Échec de la mise à jour de /etc/hosts (sudo refusé ?)")


def handle_http_ports(ip, ports, nmap_output, box_name):
    """
    Gère les ports HTTP/HTTPS détectés :
      - Affiche les ports ouverts
      - Extrait automatiquement les hostnames depuis le résultat nmap
      - Si rien trouvé → demande à l'utilisateur de coller l'URL manuellement
      - Propose de mettre à jour /etc/hosts
    """
    http_ports = check_http_port(ports)
    if not http_ports:
        return

    print(f"\n{C.GREEN}{C.BOLD}[+] Port(s) HTTP/HTTPS détecté(s) :{C.RESET}")
    for p in http_ports:
        print(f"    {C.CYAN}{p['port']}/tcp{C.RESET}  {p['service']}  {p['version']}")

    # ── Extraction automatique ──────────────────────────────────────
    hostnames = extract_hostnames_from_nmap(nmap_output)

    if hostnames:
        print(f"\n{C.GREEN}[+] Hostname(s) détecté(s) automatiquement :{C.RESET}")
        for i, h in enumerate(hostnames, 1):
            print(f"    {C.CYAN}[{i}]{C.RESET} {h}")

        confirm = input(
            f"\nAjouter dans /etc/hosts ? [O/n] "
        ).strip().lower()
        if confirm == 'n':
            info("Mise à jour /etc/hosts ignorée.")
            return

        update_hosts_file(ip, hostnames, box_name)

    else:
        # ── Aucun hostname trouvé → saisie manuelle ──────────────────
        print(f"\n{C.YELLOW}[!] Aucun hostname trouvé automatiquement dans le résultat nmap.{C.RESET}")
        print(f"    Le port 80 est ouvert —->  un site web est accessible.")
        print(f"    Coller URL ou le hostname visible dans le résultat nmap ci-dessus.")
        print(f"    Exemples : cctv.htb   /   http://cctv.htb/   /   www.cctv.htb")

        raw = input(f"\n{C.BOLD}URL / hostname >{C.RESET} ").strip()
        if not raw:
            info("Aucune saisie — /etc/hosts non modifié.")
            return

        # Nettoie l'URL collée (retire http://, slash final, espaces)
        cleaned = re.sub(r'^https?://', '', raw).rstrip('/').strip()
        if not cleaned:
            warn("Valeur invalide, /etc/hosts non modifié.")
            return

        info(f"Hostname retenu : {cleaned}")
        update_hosts_file(ip, [cleaned], box_name)


# ─────────────────────────────────────────────
# MENU PRINCIPAL
# ─────────────────────────────────────────────

def menu_box_choice():
    """Menu : nouvelle box ou reprise."""
    print(f"\n{C.BOLD}Que veux-tu faire ?{C.RESET}")
    print(f"  {C.CYAN}[1]{C.RESET} Commencer une nouvelle box")
    print(f"  {C.CYAN}[2]{C.RESET} Reprendre une box existante")
    print(f"  {C.CYAN}[0]{C.RESET} Quitter")

    while True:
        choice = input(f"\n{C.BOLD}Choix >{C.RESET} ").strip()
        if choice in ("0", "1", "2"):
            return choice
        warn("Entre 0, 1 ou 2.")


def menu_action(is_resume=False):
    """Menu : que faire après avoir ouvert la box."""
    print(f"\n{C.BOLD}Que veux-tu faire ?{C.RESET}")
    print(f"  {C.CYAN}[1]{C.RESET} Lancer un scan nmap")
    if is_resume:
        print(f"  {C.CYAN}[2]{C.RESET} Mettre à jour l'IP dans /etc/hosts")
    print(f"  {C.CYAN}[0]{C.RESET} Quitter (continuer à la main)")

    valid = ("0", "1", "2") if is_resume else ("0", "1")
    while True:
        choice = input(f"\n{C.BOLD}Choix >{C.RESET} ").strip()
        if choice in valid:
            return choice
        warn(f"Entre une option valide : {', '.join(valid)}.")


# ─────────────────────────────────────────────
# MISE À JOUR IP DANS /ETC/HOSTS
# ─────────────────────────────────────────────

def update_hosts_ip(box_name):
    """
    Trouve les lignes HTB de cette box dans /etc/hosts,
    affiche l'IP actuelle, demande la nouvelle IP et remplace.
    Si rien n'est trouvé → ouvre nano pour modification manuelle.
    """
    tag = f"# HTB - {box_name}"

    try:
        with open(HOSTS_FILE, "r") as f:
            lines = f.readlines()
    except Exception as e:
        error(f"Impossible de lire {HOSTS_FILE} : {e}")
        return

    # Trouve les lignes appartenant à cette box
    matching = [(i, line.rstrip()) for i, line in enumerate(lines) if tag in line]

    if not matching:
        warn(f"Aucune entrée '{tag}' trouvée dans {HOSTS_FILE}.")
        warn("Ouverture de /etc/hosts dans nano pour modification manuelle...")
        print(f"{C.YELLOW}(Mot de passe sudo requis){C.RESET}")
        subprocess.run(["sudo", "nano", HOSTS_FILE])
        return

    # Affiche ce qui a été trouvé
    print(f"\n{C.BOLD}Entrées trouvées pour '{box_name}' :{C.RESET}")
    for i, line in matching:
        # Extrait l'IP actuelle (premier token)
        current_ip = line.split()[0] if line.split() else "???"
        print(f"  ligne {i+1:3d} │ {C.CYAN}{current_ip:<18}{C.RESET}{line[len(current_ip):]}")

    # Demande la nouvelle IP
    new_ip = input(f"\n{C.BOLD}Nouvelle IP >{C.RESET} ").strip()
    if not new_ip:
        info("Aucune IP saisie — /etc/hosts non modifié.")
        return
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', new_ip):
        warn(f"'{new_ip}' ne ressemble pas à une IP valide.")
        confirm = input("Continuer quand même ? [o/N] ").strip().lower()
        if confirm != 'o':
            return

    # Construit le nouveau contenu en remplaçant l'IP sur les lignes concernées
    new_lines = list(lines)
    for i, line in matching:
        tokens = line.split()
        if tokens:
            # Remplace uniquement le premier token (l'IP)
            old_ip = tokens[0]
            new_lines[i] = line.replace(old_ip, new_ip, 1) + ("\n" if not line.endswith("\n") else "")

    # Aperçu des changements
    print(f"\n{C.BOLD}Changements à appliquer :{C.RESET}")
    for i, line in matching:
        print(f"  {C.RED}- {lines[i].rstrip()}{C.RESET}")
        print(f"  {C.GREEN}+ {new_lines[i].rstrip()}{C.RESET}")

    confirm = input(f"\nAppliquer ? [O/n] ").strip().lower()
    if confirm == 'n':
        info("/etc/hosts non modifié.")
        return

    # Écrit le nouveau contenu via sudo tee
    new_content = "".join(new_lines)
    print(f"{C.YELLOW}(Mot de passe sudo requis){C.RESET}")
    result = subprocess.run(
        f"echo {repr(new_content)} | sudo tee {HOSTS_FILE} > /dev/null",
        shell=True
    )
    if result.returncode == 0:
        success(f"/etc/hosts mis à jour ✓  (ancienne IP remplacée par {new_ip})")
    else:
        error("Échec de l'écriture dans /etc/hosts (sudo refusé ?)")
        warn("Ouverture dans nano pour modification manuelle...")
        subprocess.run(["sudo", "nano", HOSTS_FILE])


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    banner()

    # Vérifie que le dossier CherryTree existe
    if not os.path.isdir(CHERRYTREE_DIR):
        error(f"Dossier introuvable : {CHERRYTREE_DIR}")
        sys.exit(1)

    # ── CHOIX BOX ──────────────────────────────
    choice = menu_box_choice()

    if choice == "0":
        info("À bientôt !")
        sys.exit(0)

    ctb_path = None
    box_name = None

    if choice == "1":
        # Nouvelle box
        ctb_path, box_name = create_new_box()
        if not ctb_path:
            error("Création annulée.")
            sys.exit(1)

    elif choice == "2":
        # Box existante
        ctb_path = select_existing_box()
        if not ctb_path:
            info("Aucune box sélectionnée. À bientôt !")
            sys.exit(0)
        box_name = os.path.basename(ctb_path).replace(".ctb", "")
        success(f"Box sélectionnée : {box_name}")

    # Ouvre CherryTree
    open_cherrytree(ctb_path)

    # ── ACTION ─────────────────────────────────
    is_resume = (choice == "2")
    action = menu_action(is_resume=is_resume)

    if action == "0":
        info("Script terminé. Bon pentest ! 🎯")
        sys.exit(0)

    # ── MISE À JOUR IP /etc/hosts (reprise uniquement) ──
    if action == "2":
        update_hosts_ip(box_name)
        info("Script terminé. Bon pentest ! 🎯")
        sys.exit(0)

    # ── NMAP ───────────────────────────────────
    ip = input(f"\n{C.BOLD}IP cible >{C.RESET} ").strip()
    if not ip:
        error("IP vide. Abandon.")
        sys.exit(1)

    if not validate_ip(ip):
        warn(f"'{ip}' ne ressemble pas à une IP valide, on continue quand même...")

    # Lance nmap
    nmap_output = run_nmap(ip)
    if not nmap_output:
        error("Scan nmap échoué ou sans résultat.")
        sys.exit(1)

    # Parse les ports
    ports = parse_open_ports(nmap_output)
    if ports:
        info(f"{len(ports)} port(s) ouvert(s) détecté(s) :")
        for p in ports:
            print(f"    {p['port']}/{p['proto']}  {p['service']}  {p['version']}")
    else:
        warn("Aucun port ouvert détecté (ou format nmap inattendu).")

    # Gère les ports HTTP → /etc/hosts
    handle_http_ports(ip, ports, nmap_output, box_name)

    # ── INTÉGRATION CHERRYTREE ──────────────────
    info("Intégration des résultats dans CherryTree...")
    try:
        conn = sqlite3.connect(ctb_path)
        tcp_node_id = find_tcp_services_node(conn)

        if tcp_node_id is None:
            warn("Nœud 'TCP Services' introuvable dans le fichier .ctb")
            warn("Vérifie que le template contient bien un nœud 'TCP Services'")
            # Debug : affiche l'arbre
            info("Nœuds disponibles dans le fichier :")
            cur = conn.cursor()
            cur.execute("SELECT node_id, name FROM node LIMIT 30")
            for row in cur.fetchall():
                print(f"    [{row[0]}] {row[1]}")
        else:
            success(f"Nœud TCP Services trouvé (ID: {tcp_node_id})")
            append_nmap_to_tcp_node(conn, tcp_node_id, ip, nmap_output)

        conn.close()

    except sqlite3.Error as e:
        error(f"Erreur SQLite : {e}")
        error("Le fichier .ctb est peut-être corrompu ou d'un format différent.")

    print(f"\n{C.GREEN}{C.BOLD}✓ Terminé ! Happy Hacking 🚀{C.RESET}")
    print(f"  Box    : {box_name}")
    print(f"  IP     : {ip}")
    print(f"  Fichier: {ctb_path}\n")


if __name__ == "__main__":
    main()
