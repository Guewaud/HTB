# HTB Automation — CherryTree Recon Script

Script Python pour automatiser la phase de reconnaissance sur **Hack The Box**, avec intégration automatique des résultats dans **CherryTree**.

---

## 🎯 Objectif

La phase de reconnaissance sur HTB implique toujours les mêmes étapes répétitives :
- Créer un fichier de notes CherryTree pour la box
- Lancer un scan nmap
- Copier les résultats dans les notes
- Ajouter l'IP et le hostname dans `/etc/hosts`

Ce script automatise l'ensemble de ces étapes en une seule commande.

---

## 📁 Structure du projet

```
.
├── htb_automatisation.py     # Script principal
├── Cherrytree/
│   └── PenTest Template.ctb  # Template de base pour chaque box
└── README.md
```

> ⚠️ Les fichiers `.ctb` des boxes actives ne sont pas versionnés (données personnelles). Seul le **template** est inclus dans le dépôt.

---

## ⚙️ Prérequis

- **OS** : Kali Linux (ou toute distribution Linux avec nmap)
- **Python** : 3.8+
- **Dépendances système** :
  ```bash
  sudo apt install nmap cherrytree
  ```
- Aucune dépendance Python externe — uniquement la bibliothèque standard

---

## 🚀 Installation

```bash
git clone https://github.com/Guewaud/Script-automatisation.git
cd Script-automatisation
chmod +x htb_automatisation.py
```

Le dossier `Cherrytree/` et le template sont inclus dans le dépôt, aucune configuration supplémentaire n'est requise.

---

## 📖 Utilisation

```bash
python3 htb_automatisation.py
```

### Menu principal

```
┌─────────────────────────────────────────┐
│  Que veux-tu faire ?                    │
│  [1] Commencer une nouvelle box         │
│  [2] Reprendre une box existante        │
│  [0] Quitter                            │
└─────────────────────────────────────────┘
```

### Nouvelle box `[1]`
1. Saisir le nom de la box (ex: `MonitorsTwo`)
2. Le script copie le template → crée `Cherrytree/MonitorsTwo.ctb`
3. CherryTree s'ouvre automatiquement avec le fichier créé
4. Choix : lancer un scan nmap ou quitter

### Reprendre une box `[2]`
1. La liste des boxes existantes s'affiche
2. Sélection de la box souhaitée
3. CherryTree s'ouvre, puis deux options :
   - **Lancer un nmap** → résultats ajoutés dans le nœud *TCP Services*
   - **Mettre à jour l'IP dans /etc/hosts** → utile quand l'IP de la box a changé entre deux sessions

---

## 🔍 Scan nmap

Commande exécutée : `nmap -sV -sC -O <IP>`

Après le scan :
- Les résultats sont **intégrés automatiquement** dans le nœud `Enumeration → TCP Services` du fichier CherryTree
- Si le **port 80/443 est ouvert**, le script détecte automatiquement le hostname dans la sortie nmap (redirection HTTP, certificat SSL, etc.) et propose de l'ajouter dans `/etc/hosts`
- Si le hostname n'est pas détecté automatiquement, saisie manuelle possible

### Exemple de détection automatique
Ligne nmap :
```
|_http-title: Did not follow redirect to http://cctv.htb/
```
Le script détecte `cctv.htb` et propose :
```
[+] Hostname(s) détecté(s) : cctv.htb
Ajouter dans /etc/hosts ? [O/n]
```
Résultat dans `/etc/hosts` :
```
10.129.18.70    cctv.htb    # HTB - CCTV
```

---

## 🔄 Mise à jour de l'IP entre deux sessions

Les IPs HTB changent à chaque reset de machine. En mode **reprise**, l'option `[2]` retrouve automatiquement la ligne correspondant à la box dans `/etc/hosts` grâce au tag `# HTB - <NomBox>` et remplace l'ancienne IP par la nouvelle.

```
Entrées trouvées pour 'CCTV' :
  ligne  42 │ 10.129.18.70    cctv.htb    # HTB - CCTV

Nouvelle IP > 10.129.25.103

Changements à appliquer :
  - 10.129.18.70    cctv.htb    # HTB - CCTV
  + 10.129.25.103   cctv.htb    # HTB - CCTV

Appliquer ? [O/n]
```

---

## 📝 Structure du template CherryTree

Le fichier `PenTest Template.ctb` contient une arborescence de notes prête à l'emploi :

```
📁 Target 1
 ├── 📁 Enumeration
 │    ├── TCP Services       ← résultats nmap intégrés ici
 │    ├── UDP Services
 │    └── 📁 Web Services
 │         ├── Nikto
 │         ├── Dirb/DirBuster
 │         ├── WebDav
 │         ├── CMS
 │         └── Other Tools
 ├── 📁 Exploitation
 ├── 📁 Post Exploitation
 ├── ⚠️  Priv Escalation
 └── 📁 Goodies
      ├── Hashes
      └── Passwords
```

---

## ⚠️ Points importants

- La modification de `/etc/hosts` nécessite **sudo** (demandé uniquement au moment de l'écriture)
- CherryTree doit être **fermé** avant d'intégrer un résultat nmap pour éviter les conflits d'écriture sur le `.ctb`. Recharger ensuite le fichier dans CherryTree (`Fichier → Recharger`)
- Les fichiers `.ctb` des boxes sont exclus du dépôt via `.gitignore` — les notes restent en local

---

## 📄 Licence

Projet open source à usage éducatif dans le cadre de Hack The Box.
