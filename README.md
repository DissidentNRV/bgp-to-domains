# bgp-to-domains
# 🛰️ ASN/IP → Domain Scanner

A fast, research-oriented desktop tool to map **ASNs or IPv4s** to their associated **domains and IPs** via [bgp.he.net](https://bgp.he.net/).  
Built with a **modern, responsive CustomTkinter UI**, supporting **up to 2048 threads**, **proxy rotation**, and **real-time logs**.

---

## 🌍 English

### ✨ Features
- 🧠 **Cooperative multithreading** — All threads work together on shared tasks (up to 2048).
- 🌐 **Proxy rotation** — Load your proxy list and randomize outgoing requests.
- 🧾 **Real-time logs & ETA** — Live progress, prefixes processed, and estimated remaining time.
- 🔢 **Prefix counter** — Shows processed / total prefixes to visualize load distribution.
- 💾 **Flexible output** — Save results in single files or per-prefix files.
- 🎨 **Modern UI** — Responsive design (dark/light/system themes).
- 🧭 **Simple workflow** — 3-step process: Targets → Options → Scan & Logs.
- ⌨️ **Shortcuts** — F5=start, Space=pause/resume, Esc=stop.

### 🚀 Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/DissidentNRV/bgp-to-domains.git
      ```

2. Create a virtual environment and install dependencies:
   ```bash
   python -m venv .venv
   # Windows:
   .venv\Scripts\activate
   # macOS / Linux:
   source .venv/bin/activate

   pip install -r requirements.txt
   ```

3. Run the app:
   ```bash
   python asn_scanner.py
   ```

### 🧩 Requirements
- Python **3.10+**
- Libraries:
  - `customtkinter`
  - `requests`
  - `beautifulsoup4`

Install with:
```bash
pip install -r requirements.txt
```

### ⚙️ Usage
1. Paste or import a list of **ASNs** or **IPv4 addresses** (one per line).  
2. Adjust options:
   - Threads (1–2048)
   - Save mode (single file / per-prefix)
   - Optional proxy list (one proxy per line)
3. Click **Start** (or press F5). Monitor logs and progress.
4. Results saved to `domains_all.txt` and `ips_all.txt` (or per-prefix files).

### 🧪 Example
Input:
```
AS15169
AS32934
8.8.8.8
```
Possible outputs:
- `domains_all.txt`  
- `ips_all.txt`  
Or per-prefix files like `domains_8.8.8.8_32.txt`.

### 🛡️ Legal & Ethics
Use responsibly. Respect target websites' Terms of Service and applicable laws. This tool is intended for educational and research purposes only.

### 📸 Interface Preview
Add screenshots in the `assets/` directory or update this README with images.

---

## 🇫🇷 Français

### ✨ Fonctionnalités
- 🧠 **Multithreading coopératif** — Tous les threads consomment une file de tâches partagée (jusqu’à 2048).
- 🌐 **Rotation de proxys** — Charge une liste de proxys pour varier les requêtes.
- 🧾 **Logs & ETA en temps réel** — Progression, préfixes traités et ETA.
- 🔢 **Compteur de préfixes** — Affiche préfixes traités / total pour visualiser la charge.
- 💾 **Sortie flexible** — Sauvegarde dans un fichier global ou par préfixe.
- 🎨 **Interface moderne** — Design responsive (thèmes sombre/clair/système).
- 🧭 **Flux simple** — 3 étapes : Cibles → Options → Scan & Logs.
- ⌨️ **Raccourcis** — F5=démarrer, Espace=pause/reprise, Échap=stop.

### 🚀 Installation
1. Cloner le dépôt :
   ```bash
   git clone https://github.com/DissidentNRV/bgp-to-domains.git
   ```

2. Créer un environnement virtuel et installer les dépendances :
   ```bash
   python -m venv .venv
   # Windows:
   .venv\Scripts\activate
   # macOS / Linux:
   source .venv/bin/activate

   pip install -r requirements.txt
   ```

3. Lancer l'application :
   ```bash
   python asn_scanner.py
   ```

### ⚙️ Pré-requis
- Python **3.10+**
- Bibliothèques :
  - `customtkinter`
  - `requests`
  - `beautifulsoup4`

Installer avec :
```bash
pip install -r requirements.txt
```

### ⚙️ Utilisation
1. Collez ou importez une liste d’**ASNs** ou d’**IPv4** (une entrée par ligne).  
2. Choisissez les options :
   - Nombre de threads (1–2048)
   - Mode de sauvegarde (fichier unique / par préfixe)
   - Optionnel : liste de proxys
3. Cliquez **Start** (ou appuyez sur F5). Surveillez les logs et la progression.
4. Les résultats sont enregistrés dans `domains_all.txt` et `ips_all.txt` (ou par préfixe).

### 🧪 Exemple
Entrée :
```
AS15169
AS32934
8.8.8.8
```
Sorties possibles :
- `domains_all.txt`  
- `ips_all.txt`  
Ou fichiers par préfixe comme `domains_8.8.8.8_32.txt`.

### 🛡️ Légal & Éthique
Utilisez de manière responsable. Respectez les CGU des sites et la législation applicable. Outil destiné à la recherche et à l'éducation.

---

## 📦 Files
- `asn_scanner.py` — Main application (CustomTkinter UI + scanning logic)
- `requirements.txt` — Python dependencies
- `README.md` — This file

## 📝 License
MIT License © 2025 — Educational and research use.

## 🤝 Contributing
Contributions welcome: open issues, propose improvements, or submit PRs. Please document changes and keep UI and scraping logic separate where possible.

---
