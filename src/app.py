import os
import hashlib
import sqlite3
import re
import platform
import threading
import json
import base64
import math
from datetime import datetime, timedelta
from collections import Counter
from werkzeug.utils import secure_filename

# Third-party imports with installation hints
try:
    from flask import Flask, render_template_string, request, jsonify, redirect, url_for, g
    from flask_socketio import SocketIO
    from PIL import Image, ExifTags
    import PyPDF2
    import docx
    from regipy.registry import RegistryHive, RegistryKeyNotFoundException
    from stegano import lsb
    from scapy.all import rdpcap, DNSQR, sniff, IP, TCP, UDP
except ImportError as e:
    print(f"Missing dependency: {e}. Please install: flask flask-socketio eventlet scapy Pillow PyPDF2 python-docx regipy stegano")
    exit()

app = Flask(__name__)
UPLOAD_FOLDER = 'temp_uploads'
DATABASE_FILE = 'forensic_cases.db'

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = os.urandom(24)
socketio = SocketIO(app, async_mode='eventlet')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Sniffer thread control
sniffer_thread = None
stop_sniffing_event = threading.Event()
sniffing_logs = {}

# --- Database Management ---

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE_FILE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS cases (
            case_id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_name TEXT NOT NULL,
            investigator_name TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS evidence (
            evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER,
            tool_used TEXT,
            evidence_summary TEXT,
            full_result TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (case_id) REFERENCES cases (case_id)
        )
        ''')
        db.commit()

# --- Forensic Utilities ---

def hash_file(file_path):
    if not os.path.exists(file_path):
        return {'error': f"File not found: '{file_path}'"}
    
    md5, sha256 = hashlib.md5(), hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5.update(chunk)
            sha256.update(chunk)
            
    return {
        'filename': os.path.basename(file_path),
        'md5': md5.hexdigest(),
        'sha256': sha256.hexdigest()
    }

def get_exif_data(image_path):
    results = [f"--- EXIF: {os.path.basename(image_path)} ---"]
    if not os.path.exists(image_path):
        return f"Error: Not found: '{image_path}'"
    
    try:
        img = Image.open(image_path)
        exif = img._getexif()
        if not exif:
            return "No EXIF data found."
            
        for tid, val in exif.items():
            tag = ExifTags.TAGS.get(tid, tid)
            val = val.decode('utf-8', 'ignore') if isinstance(val, bytes) else val
            results.append(f"{str(tag):<25}: {str(val)}")
        return "\n".join(results)
    except Exception as e:
        return f"Error getting EXIF: {e}"

def analyze_pcap(pcap_path):
    results = [f"--- PCAP DNS: {os.path.basename(pcap_path)} ---"]
    if not os.path.exists(pcap_path):
        return f"Error: Not found: '{pcap_path}'"
        
    try:
        queries = sorted(list(set(p[DNSQR].qname.decode() for p in rdpcap(pcap_path) if p.haslayer(DNSQR))))
        results.append(f"\n--- Found {len(queries)} unique DNS Queries ---")
        results.extend(f"  - {q}" for q in queries)
        return "\n".join(results)
    except Exception as e:
        return f"Error analyzing PCAP: {e}"

def extract_strings(file_path):
    results = [f"--- Strings: {os.path.basename(file_path)} ---"]
    if not os.path.exists(file_path):
        return f"Error: Not found: '{file_path}'"
        
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        strings = re.findall(b"[\x20-\x7E]{4,}", content)
        results.append(f"Found {len(strings)} strings (4+ chars):\n")
        results.extend(s.decode('ascii', 'ignore') for s in strings)
        return "\n".join(results)
    except Exception as e:
        return f"Error extracting strings: {e}"

def get_doc_metadata(doc_path):
    results = [f"--- Metadata: {os.path.basename(doc_path)} ---"]
    if not os.path.exists(doc_path):
        return f"Error: Not found: '{doc_path}'"
        
    try:
        meta_found = False
        if doc_path.lower().endswith('.pdf'):
            with open(doc_path, 'rb') as f:
                meta = PyPDF2.PdfReader(f).metadata
            if meta:
                meta_found = True
                results.extend(f"{k[1:]:<20}: {v}" for k, v in meta.items())
                
        elif doc_path.lower().endswith('.docx'):
            props = docx.Document(doc_path).core_properties
            prop_dict = {}
            for p in ['author', 'category', 'comments', 'content_status', 'created', 'identifier', 
                      'keywords', 'language', 'last_modified_by', 'last_printed', 'modified', 
                      'revision', 'subject', 'title', 'version']:
                try:
                    val = getattr(props, p)
                    if val: prop_dict[p] = val
                except AttributeError:
                    pass
            if prop_dict:
                meta_found = True
                results.extend(f"{p:<20}: {v}" for p, v in prop_dict.items())
                
        if not meta_found:
            results.append("No metadata found.")
        return "\n".join(results)
    except Exception as e:
        return f"Error getting doc metadata: {e}"

def parse_browser_history(history_path):
    results = [f"--- Browser History: {history_path or 'Default Location'} ---"]
    hist_path_to_use = history_path
    
    if not hist_path_to_use:
        user_home = os.path.expanduser('~')
        if platform.system() == 'Windows':
            hist_path_to_use = os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Google', 'Chrome', 'User Data', 'Default', 'History')
        elif platform.system() == 'Darwin':
            hist_path_to_use = os.path.join(user_home, 'Library', 'Application Support', 'Google', 'Chrome', 'Default', 'History')
        elif platform.system() == 'Linux':
             hist_path_to_use = os.path.join(user_home, '.config', 'google-chrome', 'Default', 'History')
    
    if not hist_path_to_use or not os.path.exists(hist_path_to_use):
        return f"Error: History file not found at '{hist_path_to_use}'"

    temp_history_file = os.path.join(app.config['UPLOAD_FOLDER'], f'history_copy_{os.getpid()}')
    
    try:
        import shutil
        shutil.copyfile(hist_path_to_use, temp_history_file)
        
        con = sqlite3.connect(temp_history_file)
        rows = con.execute("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 20").fetchall()
        con.close()
        
        if not rows:
            return "\n".join(results) + "\nNo history entries found."
            
        results.append("\n--- Found Top 20 Most Recent URLs ---")
        for r in rows:
            url = r[0] or "[No URL]"
            title = r[1] or "[No Title]"
            last_visit_micro = r[3] or 0
            try:
                ts = datetime(1601, 1, 1) + timedelta(microseconds=last_visit_micro)
                ts_str = ts.strftime('%Y-%m-%d %H:%M:%S')
            except OverflowError:
                ts_str = "[Invalid Timestamp]"
            
            results.append(f"\nURL: {url}\nTitle: {title}\nLast Visit: {ts_str}")
            
        return "\n".join(results)
        
    except sqlite3.OperationalError as e:
        return f"Error: {e}\n(Hint: Make sure Chrome is fully closed before running this tool.)"
    except Exception as e:
        return f"Error parsing history: {e}"
    finally:
        if os.path.exists(temp_history_file):
            try:
                os.remove(temp_history_file)
            except Exception:
                pass

def keyword_search(directory, keyword):
    results = [f"--- Keyword Search: '{keyword}' in '{directory}' ---"]
    if not directory or not os.path.isdir(directory):
        return f"Error: Invalid directory: '{directory}'"
    if not keyword:
        return "Error: Keyword cannot be empty."
        
    found = []
    try:
        for root, _, files in os.walk(directory):
            for file in files:
                path = os.path.join(root, file)
                # Try reading as text with multiple encodings
                file_found = False
                for enc in ['utf-8', 'latin-1', 'ascii']:
                    try:
                        with open(path, 'r', encoding=enc) as f:
                            if keyword in f.read():
                                found.append(path)
                                file_found = True
                                break
                    except (UnicodeDecodeError, Exception):
                        continue
                
                # If not found as text, check binary
                if not file_found:
                    try:
                         with open(path, 'rb') as f:
                             if keyword.isascii() and keyword.encode('ascii') in f.read():
                                 found.append(f"{path} (Keyword found in binary)")
                    except Exception:
                        pass
                        
        results.extend(f"[+] Found in: {fpath}" for fpath in found)
        results.append(f"\nSearch complete. Found {len(found)} occurrences.")
    except Exception as e:
        return f"Error during search: {e}"
        
    return "\n".join(results)

def carve_files(data_file):
    results = [f"--- Carving JPEGs: {os.path.basename(data_file)} ---"]
    if not os.path.exists(data_file):
        return f"Error: Not found: '{data_file}'"
        
    jpeg_header = rb'\xff\xd8\xff'
    jpeg_footer = rb'\xff\xd9'
    found = 0
    output_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'carved_output')
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        with open(data_file, 'rb') as f:
            data = f.read()
            
        starts = [m.start() for m in re.finditer(re.escape(jpeg_header), data)]
        if not starts:
            return "No JPEG headers (FF D8 FF) found."
            
        for i, start in enumerate(starts):
            foot = data.find(jpeg_footer, start + len(jpeg_header))
            if foot != -1:
                end = foot + len(jpeg_footer)
                img_data = data[start : end]
                
                if len(img_data) > 1024:
                    out_filename = f"carved_img_{start}_{end}.jpg"
                    out_path = os.path.join(output_dir, out_filename)
                    try:
                        with open(out_path, 'wb') as outfile:
                            outfile.write(img_data)
                        results.append(f"[+] Carved JPEG: Size {len(img_data)} bytes @ offset {start} -> {out_filename}")
                        found += 1
                    except Exception as write_e:
                        results.append(f"[!] Error writing {out_filename}: {write_e}")
                        
        results.append(f"\nCarving complete. Found/saved {found} JPEGs in '{output_dir}'.")
        return "\n".join(results)
    except Exception as e:
        return f"Error carving: {e}"

def parse_registry_usb(registry_hive):
    results = [f"--- USB History: {os.path.basename(registry_hive)} ---"]
    if platform.system() != "Windows":
        return "Error: Windows only."
    if not os.path.exists(registry_hive):
        return f"Error: Not found: '{registry_hive}'"
        
    try:
        reg = RegistryHive(registry_hive)
        usbstor_key = None
        common_paths = [r"ControlSet001\Enum\USBSTOR", r"ControlSet002\Enum\USBSTOR", r"CurrentControlSet\Enum\USBSTOR"]
        
        for key_path in common_paths:
             try:
                 usbstor_key = reg.get_key(key_path)
                 break
             except RegistryKeyNotFoundException:
                 continue
                 
        if not usbstor_key:
            # Fallback to 'Select' key
            try:
                select_key = reg.get_key('Select')
                current_control_set_num = select_key.get_value('Current')
                if current_control_set_num:
                    key_path = rf"ControlSet{current_control_set_num:03d}\Enum\USBSTOR"
                    usbstor_key = reg.get_key(key_path)
            except (RegistryKeyNotFoundException, TypeError, ValueError):
                pass
                
        if not usbstor_key:
            return "Error: USBSTOR key not found."
            
        results.append(f"--- Found {usbstor_key.number_of_subkeys} USB Devices ---")
        for subkey in usbstor_key.iter_subkeys():
            results.append(f"\n[+] Device: {subkey.name}")
            for dev_key in subkey.iter_subkeys():
                results.append(f"  - Instance: {dev_key.name}")
                try:
                    friendly = reg.get_value(dev_key.path, 'FriendlyName')
                    results.append(f"    - Friendly Name: {friendly}")
                except RegistryKeyNotFoundException:
                    pass
                results.append(f"    - Last Write Time: {dev_key.timestamp}")
        return "\n".join(results)
    except Exception as e:
        return f"Error parsing registry: {e}\n(Hint: Run as Admin & use correct hive file.)"

def stego_tool(mode, image_path, message):
    results = [f"--- Stego (Mode: {mode}) ---"]
    if not os.path.exists(image_path):
        return f"Error: Not found: '{image_path}'"
    try:
        if mode == 'hide':
            return "[Hide mode not supported.]"
        elif mode == 'reveal':
            results.append(f"Revealing from '{os.path.basename(image_path)}'...")
            secret = lsb.reveal(image_path)
            results.append("\n--- SECRET MESSAGE ---" if secret else "No message found.")
            if secret:
                results.append(secret)
                results.append("--------------------")
        return "\n".join(results)
    except Exception as e:
        return f"Error during steganography operation: {e}"

def base64_tool(mode, input_data):
    results = [f"--- Base64 ({mode}) ---"]
    try:
        if mode == 'encode':
            if isinstance(input_data, str):
                input_data = input_data.encode('utf-8')
            res = base64.b64encode(input_data).decode('ascii')
            results.append(f"Encoded:\n{res}")
        elif mode == 'decode':
            if isinstance(input_data, str):
                input_data = input_data.encode('ascii')
            padding = len(input_data) % 4
            if padding != 0:
                input_data += b'=' * (4 - padding)
            res = base64.b64decode(input_data).decode('utf-8', 'ignore')
            results.append(f"Decoded:\n{res}")
        return "\n".join(results)
    except Exception as e:
        return f"Error decoding Base64: {e}"

def rot13_tool(input_text):
    results = [f"--- ROT13 ---"]
    try:
        import codecs
        results.append("Result:")
        results.append(codecs.encode(input_text, 'rot_13'))
    except Exception as e:
        return f"Error applying ROT13: {e}"
    return "\n".join(results)

def xor_tool(input_data, key_str, key_type):
    results = [f"--- XOR ---"]
    try:
        key = bytes.fromhex(key_str) if key_type == 'hex' else key_str.encode('utf-8')
        if not key:
            return "Error: Key empty."
        if isinstance(input_data, str):
            input_data = input_data.encode('utf-8', 'ignore')
        
        out = bytearray(b ^ key[i % len(key)] for i, b in enumerate(input_data))
        
        try:
            results.append(f"Result (UTF-8):\n{out.decode('utf-8')}")
        except UnicodeDecodeError:
            results.append(f"Result (Hex):\n{out.hex()}")
        return "\n".join(results)
    except Exception as e:
        return f"Error applying XOR: {e}"

def calculate_entropy(file_path):
    results = [f"--- Entropy: {os.path.basename(file_path)} ---"]
    if not os.path.exists(file_path):
        return f"Error: Not found: '{file_path}'"
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        size = len(data)
        if size == 0:
            return "File empty (Entropy=0)."
            
        counts = Counter(data)
        ent = -sum((c / size) * math.log2(c / size) for c in counts.values())
        
        results.append(f"Size: {size} bytes")
        results.append(f"Entropy: {ent:.4f} bits/byte")
        results.append("\nInterpretation:\n ~0: Repetitive\n 4-6: Text/Structured\n ~8: Random (Encrypted/Compressed)")
        return "\n".join(results)
    except Exception as e:
        return f"Error calculating entropy: {e}"

# --- HTML Templates ---

HOME_HTML = r"""
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8"> <meta name="viewport" content="width=device-width, initial-scale=1.0"> <title>Welcome - Digital Forensic Toolkit</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com"> <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin> <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link href="https://unpkg.com/aos@2.3.1/dist/aos.css" rel="stylesheet">
    <style>
        html { scroll-behavior: smooth; }
        body { font-family: 'Inter', sans-serif; background-color: #111827; overflow-x: hidden; }
        .neon-stroke-text { color: transparent; -webkit-text-stroke: 1px #0ea5e9; text-stroke: 1px #0ea5e9; text-shadow: 0 0 5px rgba(14, 165, 233, 0.7), 0 0 10px rgba(14, 165, 233, 0.5), 0 0 20px rgba(14, 165, 233, 0.3); }
        .dashboard-button { background: #0ea5e9; color: white; font-weight: 600; font-size: 1.25rem; border-radius: 0.5rem; padding: 1rem 2.5rem; transition: all 0.2s; box-shadow: 0 4px 20px -5px rgba(14, 165, 233, 0.5); text-decoration: none; display: inline-block; }
        .dashboard-button:hover { background: #0284c7; transform: translateY(-3px); box-shadow: 0 7px 25px -5px rgba(14, 165, 233, 0.6); }
        .feature-card { background-color: #1f2937; border: 1px solid #374151; border-radius: 0.5rem; padding: 2.5rem; transition: all 0.2s; text-align: left; }
        .image-placeholder { width: 100%; max-width: 600px; height: 400px; border-radius: 0.5rem; object-fit: cover; border: 1px solid #374151; transition: border-color 0.2s; }
        .scroll-section { min-height: 100vh; width: 100vw; display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center; padding: 2rem; }
        .neon-stroke-text-green { color: transparent; -webkit-text-stroke: 1px #22c55e; text-stroke: 1px #22c55e; text-shadow: 0 0 5px rgba(34, 197, 94, 0.7), 0 0 10px rgba(34, 197, 94, 0.5), 0 0 20px rgba(34, 197, 94, 0.3); }
        .feature-card-green:hover { border-color: #22c55e; } .image-placeholder-green { border-color: #22c55e; }
        .neon-stroke-text-purple { color: transparent; -webkit-text-stroke: 1px #a855f7; text-stroke: 1px #a855f7; text-shadow: 0 0 5px rgba(168, 85, 247, 0.7), 0 0 10px rgba(168, 85, 247, 0.5), 0 0 20px rgba(168, 85, 247, 0.3); }
        .feature-card-purple:hover { border-color: #a855f7; } .image-placeholder-purple { border-color: #a855f7; }
        .neon-stroke-text-orange { color: transparent; -webkit-text-stroke: 1px #f97316; text-stroke: 1px #f97316; text-shadow: 0 0 5px rgba(249, 115, 22, 0.7), 0 0 10px rgba(249, 115, 22, 0.5), 0 0 20px rgba(249, 115, 22, 0.3); }
        .feature-card-orange:hover { border-color: #f97316; } .image-placeholder-orange { border-color: #f97316; }
    </style>
</head>
<body class="text-gray-300">
    <section class="scroll-section" data-aos="fade-in" data-aos-duration="1500"> <div class="max-w-4xl mx-auto"> <h1 class="text-6xl font-extrabold neon-stroke-text mb-4">Digital Forensic Toolkit</h1> <p class="text-2xl text-gray-400">Your all-in-one Python tool for digital investigation.</p> <p class="text-lg text-sky-400 mt-12 animate-pulse">Scroll down to explore</p> </div> </section>
    <section class="scroll-section" data-aos="fade-up"> <div class="max-w-3xl mx-auto"> <p class="text-3xl leading-relaxed text-gray-200 mb-10"> This application provides a suite of powerful tools designed to analyze digital evidence. Uncover hidden data, analyze system artifacts, and trace network activity with a simple, user-friendly interface. Now with persistent case management. </p> </div> </section>
    <section class="scroll-section"> <div class="max-w-6xl mx-auto grid grid-cols-1 md:grid-cols-2 gap-12 items-center"> <div data-aos="fade-right" data-aos-duration="1000"> <img src="https://placehold.co/600x400/111827/22C55E?text=File%20Analysis&font=inter" alt="File Analysis" class="image-placeholder shadow-2xl image-placeholder-green"> </div> <div class="feature-card feature-card-green" data-aos="fade-left" data-aos-duration="1000" data-aos-delay="200"> <h3 class="text-4xl font-semibold text-green-500 neon-stroke-text-green mb-4">File Analysis</h3> <p class="text-xl text-gray-300">Analyze files to find hidden metadata, check integrity with hashes, carve deleted images, detect steganography, check entropy, and handle common encodings.</p> </div> </div> </section>
    <section class="scroll-section"> <div class="max-w-6xl mx-auto grid grid-cols-1 md:grid-cols-2 gap-12 items-center"> <div class="feature-card feature-card-purple" data-aos="fade-right" data-aos-duration="1000" data-aos-delay="200"> <h3 class="text-4xl font-semibold text-purple-500 neon-stroke-text-purple mb-4">System Forensics</h3> <p class="text-xl text-gray-300">Investigate system artifacts to find USB connection history from the Windows Registry, parse browser history files, and perform keyword searches across directories.</p> </div> <div data-aos="fade-left" data-aos-duration="1000"> <img src="https://placehold.co/600x400/111827/A855F7?text=System%20Forensics&font=inter" alt="System Forensics" class="image-placeholder shadow-2xl image-placeholder-purple"> </div> </div> </section>
    <section class="scroll-section"> <div class="max-w-6xl mx-auto grid grid-cols-1 md:grid-cols-2 gap-12 items-center"> <div data-aos="fade-right" data-aos-duration="1000"> <img src="https://placehold.co/600x400/111827/F97316?text=Network%20Forensics&font=inter" alt="Network Forensics" class="image-placeholder shadow-2xl image-placeholder-orange"> </div> <div class="feature-card feature-card-orange" data-aos="fade-left" data-aos-duration="1000" data-aos-delay="200"> <h3 class="text-4xl font-semibold text-orange-500 neon-stroke-text-orange mb-4">Network Forensics</h3> <p class="text-xl text-gray-300">Analyze captured network traffic (.pcap files) and run a live packet sniffer to trace internet activity in real-time.</p> </div> </div> </section>
    <section class="scroll-section" data-aos="zoom-in"> <div class="max-w-4xl mx-auto"> <h2 class="text-4xl font-bold text-gray-200 mb-10">Manage your forensic cases</h2> <a href="/dashboard" class="dashboard-button"> Go To Case Dashboard </a> </div> </section>
    <script src="https://unpkg.com/aos@2.3.1/dist/aos.js"></script> <script> AOS.init({ once: true, duration: 800, offset: 300 }); </script>
</body>
</html>
"""

DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8"> <meta name="viewport" content="width=device-width, initial-scale=1.0"> <title>Case Management - Digital Forensic Toolkit</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com"> <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin> <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; background-color: #111827; }
        .neon-stroke-text { color: transparent; -webkit-text-stroke: 1px #0ea5e9; text-stroke: 1px #0ea5e9; text-shadow: 0 0 5px rgba(14, 165, 233, 0.7), 0 0 10px rgba(14, 165, 233, 0.5), 0 0 20px rgba(14, 165, 233, 0.3); }
        .form-input { background-color: #1f2937; border-color: #374151; color: #d1d5db; } .form-input:focus { --tw-ring-color: #0ea5e9; border-color: #0ea5e9; box-shadow: 0 0 0 2px var(--tw-ring-color); }
        .btn-primary { background: #0ea5e9; color: white; font-weight: 600; border-radius: 0.5rem; padding: 0.75rem 1.5rem; transition: all 0.2s; box-shadow: 0 4px 20px -5px rgba(14, 165, 233, 0.5); } .btn-primary:hover { background: #0284c7; transform: translateY(-2px); }
        .btn-secondary { background: #374151; color: white; font-weight: 500; border-radius: 0.5rem; padding: 0.5rem 1rem; transition: all 0.2s; } .btn-secondary:hover { background: #4b5563; }
        .case-card { background-color: #1f2937; border: 1px solid #374151; transition: all 0.2s; } .case-card:hover { transform: translateY(-5px); border-color: #0ea5e9; }
    </style>
</head>
<body class="text-gray-300 min-h-screen p-4 md:p-8">
    <div class="max-w-6xl mx-auto">
        <header class="text-center mb-12 relative"> <a href="/" class="absolute left-0 top-2 text-sky-400 hover:text-sky-300 transition-colors">&larr; Back to Introduction</a> <h1 class="text-6xl font-extrabold neon-stroke-text mb-4">Case Management</h1> <p class="text-2xl text-gray-400">Create a new case or open an existing investigation.</p> </header>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-8">
            <div class="md:col-span-1 bg-gray-800 p-6 rounded-lg shadow-2xl border border-gray-700">
                <h2 class="text-3xl font-bold text-white mb-6 neon-stroke-text">Start New Case</h2>
                <form action="/create_case" method="POST" class="space-y-4">
                    <div> <label for="case_name" class="block text-sm font-medium text-gray-300">Case Name / ID</label> <input type="text" id="case_name" name="case_name" required class="form-input w-full p-3 rounded-md mt-1" placeholder="e.g., Case-001 (Laptop)"> </div>
                    <div> <label for="investigator_name" class="block text-sm font-medium text-gray-300">Investigator Name</label> <input type="text" id="investigator_name" name="investigator_name" required class="form-input w-full p-3 rounded-md mt-1" placeholder="e.g., John Doe"> </div>
                    <button type="submit" class="btn-primary w-full !mt-6">Create & Open Case</button>
                </form>
            </div>
            <div class="md:col-span-2 bg-gray-800 p-6 rounded-lg shadow-2xl border border-gray-700">
                <h2 class="text-3xl font-bold text-white mb-6 neon-stroke-text">Open Existing Case</h2>
                <div class="space-y-4 max-h-[60vh] overflow-y-auto pr-2">
                    {% if cases %} {% for case in cases %}
                        <div class="case-card flex justify-between items-center p-4 rounded-lg">
                            <div> <h3 class="text-xl font-semibold text-sky-400">{{ case['case_name'] }}</h3> <p class="text-sm text-gray-400">Investigator: {{ case['investigator_name'] }} | Created: {{ (case['created_at'].split(' ')[0]) }}</p> </div>
                            <a href="{{ url_for('toolkit', case_id=case['case_id']) }}" class="btn-secondary">Open Case</a>
                        </div>
                    {% endfor %} {% else %} <p class="text-gray-400 text-center py-8">No existing cases found.</p> {% endif %}
                </div>
            </div>
        </div>
    </div>
</body>
</html>
"""

TOOLKIT_HTML = r"""
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8"> <meta name="viewport" content="width=device-width, initial-scale=1.0"> <title>Case #{{ case['case_id'] }} - {{ case['case_name'] }}</title>
    <script src="https://cdn.tailwindcss.com"></script> <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.5/socket.io.js"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com"> <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin> <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style> 
        body { font-family: 'Inter', sans-serif; background-color: #111827; }
        .neon-stroke-text { color: transparent; -webkit-text-stroke: 1px #0ea5e9; text-stroke: 1px #0ea5e9; text-shadow: 0 0 5px rgba(14, 165, 233, 0.7), 0 0 10px rgba(14, 165, 233, 0.5), 0 0 15px rgba(14, 165, 233, 0.3); }
        #case-log-output { background: #000; border: 1px solid #374151; border-radius: 0.5rem; min-height: 300px; max-height: 60vh; overflow-y: auto; }
        .evidence-item { border-bottom: 1px solid #374151; padding: 1rem; } .evidence-item:first-child { background-color: #1f2937; }
        .evidence-summary { display: flex; justify-content: space-between; align-items: center; font-family: 'Inter', sans-serif; cursor: pointer; }
        .evidence-summary strong { color: #0ea5e9; font-weight: 600; } .evidence-summary span { font-size: 0.8rem; color: #6b7280; }
        .evidence-full-result { display: none; white-space: pre-wrap; word-wrap: break-word; font-family: 'Courier New', Courier, monospace; background-color: #111827; padding: 1rem; margin-top: 1rem; border-radius: 0.375rem; max-height: 400px; overflow-y: auto; }
        .form-select, .form-input, .form-textarea, .form-radio { background-color: #1f2937; border-color: #374151; color: #d1d5db; }
        .form-select:focus, .form-input:focus, .form-textarea:focus { --tw-ring-color: #0ea5e9; border-color: #0ea5e9; box-shadow: 0 0 0 2px var(--tw-ring-color); }
        .form-radio { appearance: none; display: inline-block; width: 1.25em; height: 1.25em; border-radius: 50%; border: 2px solid #374151; vertical-align: middle; margin-right: 0.5em; position: relative; top: -1px; }
        .form-radio:checked { border-color: #0ea5e9; background-color: #0ea5e9; } .form-radio:checked::after { content: ''; display: block; width: 0.5em; height: 0.5em; background-color: #1f2937; border-radius: 50%; position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); }
        .form-file::file-selector-button { background: #0ea5e9; color: white; border: 0; padding: 0.5rem 1rem; border-radius: 0.375rem; font-weight: 500; cursor: pointer; } .form-file::file-selector-button:hover { background: #0284c7; }
        .run-button { background: #0ea5e9; color: white; font-weight: 600; font-size: 1.125rem; border-radius: 0.5rem; padding: 0.75rem 1.5rem; transition: all 0.2s; } .run-button:hover { background: #0284c7; transform: translateY(-2px); } .run-button:disabled { background: #374151; opacity: 0.5; cursor: not-allowed; }
        .form-group { display: none; } .form-group.active { display: block; } .info-box { display: none; } .info-box.active { display: block; }
        #download-btn { display: none; background-color: #10B981; color: white; padding: 0.5rem 1rem; border-radius: 0.375rem; font-weight: 500; text-decoration: none; text-align: center; transition: background-color 0.2s; } #download-btn:hover { background-color: #059669; } 
        #loader { display: none; border: 4px solid #374151; border-top: 4px solid #0ea5e9; border-radius: 50%; width: 50px; height: 50px; animation: spin 1s linear infinite; margin: 4rem auto; } @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .hash-table { width: 100%; border-collapse: collapse; margin-top: 1rem; } .hash-table th, .hash-table td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #374151; } .hash-table th { color: #0ea5e9; font-weight: 600; text-transform: uppercase; } .hash-table td { font-family: 'Courier New', Courier, monospace; word-break: break-all; }
    </style>
</head>
<body class="text-gray-300 min-h-screen p-4 md:p-8">
    <div class="max-w-5xl mx-auto">
        <header class="text-center mb-10 relative">
            <a href="/dashboard" class="absolute left-0 top-2 text-sky-400 hover:text-sky-300 transition-colors">&larr; Back to Case Files</a>
            <h1 class="text-5xl font-extrabold neon-stroke-text mb-3">Case: {{ case['case_name'] }}</h1>
            <p class="text-xl text-gray-400">Investigator: {{ case['investigator_name'] }} | Case ID: #{{ case['case_id'] }}</p>
        </header>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div class="bg-gray-800 p-6 rounded-lg shadow-2xl border border-gray-700">
                <form id="forensic-form">
                    <input type="hidden" name="case_id" id="case_id" value="{{ case['case_id'] }}">
                    <div class="mb-6">
                        <label for="tool" class="block text-lg font-medium text-white mb-2">1. Select a Tool</label>
                        <select id="tool" name="tool" class="form-select w-full p-3 rounded-md">
                            <option value="">-- Choose a tool --</option>
                            <optgroup label="File Analysis"> <option value="hash">File Hasher (MD5/SHA256)</option> <option value="exif">EXIF Image Analyzer</option> <option value="metadata">Document Metadata (PDF/DOCX)</option> <option value="strings">Extract Strings</option> <option value="carve">Carve JPEGs (Finds JPEGs)</option> <option value="stego_reveal">Reveal Steganography (Stego)</option> <option value="entropy">File Entropy Calculator</option> </optgroup>
                            <optgroup label="Network Analysis"> <option value="pcap_analyze">Analyze Pcap File</option> <option value="sniff">Live Packet Sniffer (Real-time)</option> </optgroup>
                            <optgroup label="System Forensics"> <option value="registry">Windows USB History</option> <option value="browser">Chrome Browser History</option> <option value="search">Keyword Searcher</option> </optgroup>
                            <optgroup label="Crypto / Encoding Tools"> <option value="base64">Base64 Encode/Decode</option> <option value="rot13">ROT13 Cipher</option> <option value="xor">XOR Cipher</option> </optgroup>
                        </select>
                    </div>
                    <div id="tool-info-box" class="info-box bg-gray-900 border border-sky-500/30 p-4 rounded-md mb-6 shadow-inner">
                        <h3 class="text-lg font-semibold text-sky-400 mb-2">Tool Information</h3> <p id="tool-description-text" class="text-gray-300 text-sm"></p>
                        <div id="tool-descriptions" class="hidden">
                            <p data-tool-info="hash"> <span class="block mb-2"><strong>What it does:</strong> Calculates a unique "digital fingerprint" (MD5 and SHA256) for any file.</span> <span class="block"><strong>Why it's used:</strong> To verify file integrity and prove that evidence has not been tampered with.</span> </p>
                            <p data-tool-info="exif"> <span class="block mb-2"><strong>What it does:</strong> Extracts hidden metadata from JPEG image files.</span> <span class="block"><strong>Why it's used:</strong> To find camera models, GPS coordinates, and timestamps, helping to establish a timeline.</span> </p>
                            <p data-tool-info="metadata"> <span class="block mb-2"><strong>What it does:</strong> Reads metadata from PDF and Microsoft Word (.docx) files.</span> <span class="block"><strong>Why it's used:</strong> To uncover author names, creation dates, and software used to create the document.</span> </p>
                            <p data-tool-info="strings"> <span class="block mb-2"><strong>What it does:</strong> Scans any file (especially binaries) and extracts all human-readable text.</span> <span class="block"><strong>Why it's used:</strong> To find clues like passwords, IPs, or URLs hidden inside non-text files like malware.</span> </p>
                            <p data-tool-info="carve"> <span class="block mb-2"><strong>What it does:</strong> Scans a raw data file (like a disk image) to find and "carve out" lost or deleted JPEGs.</span> <span class="block"><strong>Why it's used:</strong> A classic data recovery technique to retrieve files that a suspect thought they deleted.</span> </p>
                            <p data-tool-info="stego_reveal"> <span class="block mb-2"><strong>What it does:</strong> Analyzes an image to detect and reveal a secret message hidden inside it using steganography.</span> <span class="block"><strong>Why it's used:</strong> To uncover covert communication channels used for data theft or espionage.</span> </p>
                            <p data-tool-info="entropy"> <span class="block mb-2"><strong>What it does:</strong> Calculates the Shannon entropy of a file, measuring its randomness.</span> <span class="block"><strong>Why it's used:</strong> High entropy (near 8) suggests data might be encrypted or compressed. Low entropy suggests plain text or structured data.</span> </p>
                            <p data-tool-info="pcap_analyze"> <span class="block mb-2"><strong>What it does:</strong> Analyzes a network packet capture file (.pcap) and extracts all DNS queries.</span> <span class="block"><strong>Why it's used:</strong> To trace a suspect's internet activity and identify connections to malicious servers.</span> </p>
                            <p data-tool-info="sniff"> <span class="block mb-2"><strong>What it does:</strong> Captures network traffic from your computer in real-time.</span> <span class="block"><strong>Why it's used:</strong> To monitor live network connections for suspicious activity. (Requires Administrator privileges).</span> </p>
                            <p data-tool-info="registry"> <span class="block mb-2"><strong>What it does:</strong> Parses the Windows Registry (SYSTEM hive) to find a log of all connected USB storage devices.</span> <span class="block"><strong>Why it's used:</strong> To prove which physical devices were connected to a machine, complete with serial numbers.</span> </p>
                            <p data-tool-info="browser"> <span class="block mb-2"><strong>What it does:</strong> Parses the live Chrome browser history file to show recently visited sites.</span> <span class="block"><strong>Why it's used:</strong> To quickly see a user's web activity. (Note: Chrome must be closed for this to work).</span> </p>
                            <p data-tool-info="search"> <span class="block mb-2"><strong>What it does:</strong> Recursively searches every file within a directory for a specific keyword.</span> <span class="block"><strong>Why it's used:</strong> To quickly find a "needle in a haystack" and locate relevant documents in a large data set.</span> </p>
                            <p data-tool-info="base64"> <span class="block mb-2"><strong>What it does:</strong> Encodes binary data into ASCII text or decodes Base64 text back to its original form.</span> <span class="block"><strong>Why it's used:</strong> To decode obfuscated commands, scripts, or data found in web traffic, emails, or malware.</span> </p>
                            <p data-tool-info="rot13"> <span class="block mb-2"><strong>What it does:</strong> Applies a simple Caesar cipher shifting each letter 13 places (A->N, B->O, etc.).</span> <span class="block"><strong>Why it's used:</strong> To quickly de-obfuscate simple hidden messages sometimes found in CTFs or forums. Applying it twice returns the original.</span> </p>
                            <p data-tool-info="xor"> <span class="block mb-2"><strong>What it does:</strong> Applies a repeating XOR cipher to data using a provided key (text or hex).</span> <span class="block"><strong>Why it's used:</strong> To decrypt simple encrypted strings or configuration data commonly found in malware analysis.</span> </p>
                        </div>
                    </div>
                    <div class="mb-6">
                        <label class="block text-lg font-medium text-white mb-2">2. Provide Input</label>
                        <div id="group-file-upload" class="form-group space-y-4"> <input type="file" name="file_upload" class="form-file w-full text-sm text-gray-400 file:mr-4 file:py-2 file:px-4"/> </div>
                        <div id="group-registry" class="form-group space-y-4"> <input type="text" name="registry_path" class="form-input w-full p-3 rounded-md" placeholder="e.g., C:\Windows\System32\config\SYSTEM"> <p class="text-xs text-gray-400">Hint: Run as Admin and use a valid hive file, not a .reg text file.</p> </div>
                        <div id="group-browser" class="form-group space-y-4"> <input type="text" name="browser_path" class="form-input w-full p-3 rounded-md" placeholder="Leave empty for default"> <p class="text-xs text-gray-400">Hint: Make sure Chrome is fully closed before running.</p> </div>
                        <div id="group-search" class="form-group space-y-4"> <input type="text" name="search_dir" class="form-input w-full p-3 rounded-md mb-3" placeholder="Directory..."> <input type="text" name="search_keyword" class="form-input w-full p-3 rounded-md" placeholder="Keyword..."> </div>
                        <div id="group-sniff" class="form-group space-y-4"> <p class="text-gray-300">Click "Start Sniffing" to begin. Captures ~20 packets or until stopped.</p> </div>
                        <div id="group-base64" class="form-group space-y-4"> <div class="flex items-center space-x-4"> <label><input type="radio" name="base64_mode" value="encode" checked class="form-radio"> Encode</label> <label><input type="radio" name="base64_mode" value="decode" class="form-radio"> Decode</label> </div> <textarea name="text_input" rows="5" class="form-textarea w-full p-3 rounded-md" placeholder="Paste Text..."></textarea> <p class="text-center text-gray-400 my-2">OR</p> <input type="file" name="file_upload_crypto" class="form-file w-full text-sm text-gray-400 file:mr-4 file:py-2 file:px-4"/> </div>
                        <div id="group-rot13" class="form-group space-y-4"> <textarea name="text_input_rot13" rows="5" class="form-textarea w-full p-3 rounded-md" placeholder="Paste Text..."></textarea> </div>
                        <div id="group-xor" class="form-group space-y-4"> <textarea name="text_input_xor" rows="5" class="form-textarea w-full p-3 rounded-md" placeholder="Paste Text..."></textarea> <p class="text-center text-gray-400 my-2">OR</p> <input type="file" name="file_upload_xor" class="form-file w-full text-sm text-gray-400 file:mr-4 file:py-2 file:px-4"/> <div class="mt-4"> <label for="xor_key" class="block text-sm font-medium text-gray-300">XOR Key</label> <input type="text" id="xor_key" name="xor_key" class="form-input w-full p-3 rounded-md mt-1" placeholder="Enter key (e.g., secret)"> </div> <div class="flex items-center space-x-4 mt-2"> <label><input type="radio" name="xor_key_type" value="text" checked class="form-radio"> Key is Text</label> <label><input type="radio" name="xor_key_type" value="hex" class="form-radio"> Key is Hex</label> </div> </div>
                        <div id="group-entropy" class="form-group space-y-4"> <input type="file" name="file_upload_entropy" class="form-file w-full text-sm text-gray-400 file:mr-4 file:py-2 file:px-4"/> </div>
                    </div>
                    <div class="mt-8"> <button type="submit" id="run-button" class="run-button w-full"> Run Tool </button> </div>
                </form>
            </div>
            <div class="bg-gray-800 p-6 rounded-lg shadow-2xl border border-gray-700">
                <div class="flex justify-between items-center mb-4"> <h2 class="text-3xl font-extrabold text-white neon-stroke-text">Case Log</h2> <a href="#" id="download-btn" class="hidden text-sm bg-green-600 hover:bg-green-700 text-white font-bold py-2 px-4 rounded transition-colors duration-200"> Download Last Result </a> </div>
                <div id="loader"></div>
                <div id="case-log-output"> {% if evidence %} {% for item in evidence %} <div class="evidence-item"> <div class="evidence-summary"> <strong>{{ item['tool_used'] | upper }}: {{ item['evidence_summary'] }}</strong> <span>{{ item['timestamp'].split('.')[0] }}</span> </div> <pre class="evidence-full-result">{{ item['full_result'] }}</pre> </div> {% endfor %} {% else %} <p id="no-evidence-placeholder" class="text-gray-500 text-center p-8">No evidence saved yet.</p> {% endif %} </div>
            </div>
        </div> 
    </div> 
<script>
    const socket = io(); 
    const caseId = document.getElementById('case_id').value; 
    const toolSelect = document.getElementById('tool'); 
    const form = document.getElementById('forensic-form'); 
    const caseLogOutput = document.getElementById('case-log-output'); 
    const runButton = document.getElementById('run-button'); 
    const loader = document.getElementById('loader'); 
    const downloadBtn = document.getElementById('download-btn');
    const toolInfoBox = document.getElementById('tool-info-box'); 
    const toolDescriptionText = document.getElementById('tool-description-text'); 
    const descriptions = document.getElementById('tool-descriptions');
    
    const toolGroups = { 
        'hash': 'group-file-upload', 'exif': 'group-file-upload', 'metadata': 'group-file-upload',
        'strings': 'group-file-upload', 'carve': 'group-file-upload', 'stego_reveal': 'group-file-upload',
        'entropy': 'group-entropy', 
        'pcap_analyze': 'group-file-upload', 'sniff': 'group-sniff',
        'registry': 'group-registry', 'browser': 'group-browser', 'search': 'group-search',
        'base64': 'group-base64', 'rot13': 'group-rot13', 'xor': 'group-xor'
    };

    let isSniffing = false; 
    let lastResultText = ""; 

    function renderNewEvidenceItem(item) {
        const placeholder = document.getElementById('no-evidence-placeholder');
        if (placeholder) placeholder.remove();
        const oldTopItem = caseLogOutput.querySelector('.evidence-item:first-child');
        if(oldTopItem) oldTopItem.style.backgroundColor = 'transparent';

        const itemDiv = document.createElement('div');
        itemDiv.className = 'evidence-item';
        itemDiv.style.backgroundColor = '#1f2937'; 
        
        let tool = item.tool_used !== undefined ? item.tool_used : item[2];
        let summary = item.evidence_summary !== undefined ? item.evidence_summary : item[3];
        let full_result = item.full_result !== undefined ? item.full_result : item[4];
        let timestamp = (item.timestamp !== undefined ? item.timestamp : item[5]).split('.')[0];
        
        const sanitizedResult = document.createElement('div');
        sanitizedResult.textContent = full_result;
        
        let content = `
            <div class="evidence-summary">
                <strong>${tool.toUpperCase()}: ${summary}</strong>
                <span>${timestamp}</span>
            </div>
            <pre class="evidence-full-result">${sanitizedResult.innerHTML}</pre> 
        `; 
        
        if (tool === 'hash' && item.pretty_result) {
             const d = item.pretty_result;
             content = `
                <div class="evidence-summary"> <strong>HASH: ${d.filename}</strong> <span>${timestamp}</span> </div>
                <div class="evidence-full-result" style="display:block;"> <table class="hash-table"> <tr><th>Algorithm</th><th>Hash</th></tr> <tr><td>MD5</td><td>${d.md5}</td></tr> <tr><td>SHA-256</td><td>${d.sha256}</td></tr> </table> </div>
            `;
        }
        itemDiv.innerHTML = content;
        caseLogOutput.prepend(itemDiv); 
    }

    function toggleEvidence(element) {
        const fullResult = element.nextElementSibling; 
        if (fullResult && fullResult.classList.contains('evidence-full-result')) {
            fullResult.style.display = (fullResult.style.display === 'block') ? 'none' : 'block';
        } else {
             const itemContainer = element.closest('.evidence-item');
             const actualFullResult = itemContainer ? itemContainer.querySelector('.evidence-full-result') : null;
             if(actualFullResult) {
                 actualFullResult.style.display = (actualFullResult.style.display === 'block') ? 'none' : 'block';
             }
        }
    }

    function showLoader() { loader.style.display = 'block'; caseLogOutput.style.display = 'none'; runButton.disabled = true; downloadBtn.style.display = 'none'; } 
    function hideLoader() { loader.style.display = 'none'; caseLogOutput.style.display = 'block'; runButton.disabled = false; }
    
    function showDownloadButton(text) {
        lastResultText = text; 
        try {
            const blob = new Blob([text], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            downloadBtn.href = url;
            const toolName = toolSelect.options[toolSelect.selectedIndex]?.text.split(' ')[0] || "result";
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            downloadBtn.download = `forensic_result_${toolName}_${timestamp}.txt`;
            downloadBtn.style.display = 'inline-block'; 
        } catch (e) {
            console.error("Error creating download link:", e);
            downloadBtn.style.display = 'none';
        }
    }

    toolSelect.addEventListener('change', () => {
        const selectedTool = toolSelect.value;
        
        document.querySelectorAll('.form-group').forEach(group => group.classList.remove('active'));
        runButton.textContent = 'Run Tool'; isSniffing = false; runButton.disabled = false; 
        
        const activeGroupId = toolGroups[selectedTool]; 
        if (activeGroupId) { 
            const activeGroupElement = document.getElementById(activeGroupId);
            if (activeGroupElement) activeGroupElement.classList.add('active'); 
        }

        const descriptionElement = descriptions.querySelector(`[data-tool-info="${selectedTool}"]`);
        if (descriptionElement) { 
            toolDescriptionText.innerHTML = descriptionElement.innerHTML; 
            toolInfoBox.classList.add('active'); 
        } else { 
            toolInfoBox.classList.remove('active'); 
            toolDescriptionText.innerHTML = ''; 
        }

        if (selectedTool === 'sniff') { runButton.textContent = 'Start Sniffing'; }
        
        downloadBtn.style.display = 'none'; 
    });

    form.addEventListener('submit', async (e) => {
        e.preventDefault(); 
        const tool = toolSelect.value;
        if (!tool) { alert('Error: Please select a tool first.'); return; }
        
        if (tool === 'sniff') {
             if (isSniffing) {
                 runButton.textContent = 'Stopping...'; runButton.disabled = true;
                 socket.emit('stop_sniffing', { case_id: caseId }); 
                 isSniffing = false;
             } else {
                 showLoader(); runButton.textContent = 'Stop Sniffing'; runButton.disabled = false;
                 isSniffing = true; socket.emit('start_sniffing', { case_id: caseId });
             }
             return;
        }
        
        showLoader();
        const formData = new FormData(form);
        
        try {
            const response = await fetch('/run', { method: 'POST', body: formData });
            if (!response.ok) { throw new Error(`HTTP error! Status: ${response.status}`); }
            const data = await response.json();
            hideLoader();
            if (data.error) { 
                alert(`Error: ${data.error}`); 
                downloadBtn.style.display = 'none'; 
            } else if (data.new_evidence) { 
                renderNewEvidenceItem(data.new_evidence);
                showDownloadButton(data.new_evidence.full_result); 
            } else {
                 alert("Received an unexpected response from the server.");
                 downloadBtn.style.display = 'none';
            }
        } catch (error) { 
            console.error('Fetch error:', error); 
            hideLoader(); 
            alert(`Client-side error: ${error.message}`); 
            downloadBtn.style.display = 'none'; 
        } 
    });

    socket.on('connect', () => { console.log('Socket.IO connected!'); });
    socket.on('packet_data', (data) => { 
        hideLoader();
        let tempSniffBox = document.getElementById('temp-sniff-output');
        if (!tempSniffBox) {
            tempSniffBox = document.createElement('div'); tempSniffBox.className = 'evidence-item'; tempSniffBox.id = 'temp-sniff-output';
            tempSniffBox.innerHTML = `<div class="evidence-summary"><strong>LIVE PACKET SNIFFER (Running...)</strong><span>Now</span></div><pre class="evidence-full-result" style="display:block;"></pre>`;
            caseLogOutput.prepend(tempSniffBox);
        }
        const pre = tempSniffBox.querySelector('pre');
        if (pre && data && data.line) { 
             pre.textContent += data.line + '\n'; pre.scrollTop = pre.scrollHeight;
        }
    });
    socket.on('sniffing_stopped', (data) => { 
        if (isSniffing) { isSniffing = false; } 
        const tempSniffBox = document.getElementById('temp-sniff-output');
        if (tempSniffBox) { tempSniffBox.remove(); }
        if(data.new_evidence) { 
            renderNewEvidenceItem(data.new_evidence);
            showDownloadButton(data.new_evidence.full_result); 
        }
        runButton.textContent = 'Start Sniffing'; runButton.disabled = false; hideLoader();
    });
    socket.on('sniffing_error', (data) => { 
        hideLoader(); alert(`Sniffing Error: ${data.error}`); 
        runButton.textContent = 'Start Sniffing'; runButton.disabled = false; isSniffing = false; 
    });

    caseLogOutput.addEventListener('click', function(event) {
        const summaryElement = event.target.closest('.evidence-summary');
        if (summaryElement) {
            toggleEvidence(summaryElement);
        }
    });

</script>
</body>
</html>
"""

# --- Routes ---

@app.route('/')
def index():
    return render_template_string(HOME_HTML)

@app.route('/dashboard')
def dashboard():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM cases ORDER BY created_at DESC")
    cases = cursor.fetchall()
    return render_template_string(DASHBOARD_HTML, cases=cases)

@app.route('/create_case', methods=['POST'])
def create_case():
    case_name = request.form.get('case_name')
    investigator_name = request.form.get('investigator_name')
    
    if not case_name or not investigator_name:
        return "Error: Case Name and Investigator Name are required.", 400
        
    db = get_db()
    cursor = db.cursor()
    cursor.execute("INSERT INTO cases (case_name, investigator_name) VALUES (?, ?)", (case_name, investigator_name))
    db.commit()
    new_case_id = cursor.lastrowid
    
    return redirect(url_for('toolkit', case_id=new_case_id))

@app.route('/toolkit/<int:case_id>')
def toolkit(case_id):
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,))
    case_data = cursor.fetchone()
    
    if not case_data:
        return "Error: Case not found.", 404
        
    cursor.execute("SELECT * FROM evidence WHERE case_id = ? ORDER BY timestamp DESC", (case_id,))
    evidence_items = cursor.fetchall()
    
    return render_template_string(TOOLKIT_HTML, case=case_data, evidence=evidence_items)

@app.route('/run', methods=['POST'])
def run_tool():
    try:
        tool = request.form.get('tool')
        case_id = request.form.get('case_id')
        
        result_text = ""
        pretty_result = None
        evidence_summary = ""
        temp_path = None
        
        # --- File Upload Logic ---
        file = None
        file_input_name = 'file_upload' # Default
        if tool == 'entropy':
            file_input_name = 'file_upload_entropy'
        elif tool in ['base64', 'xor']:
            file_crypto = request.files.get('file_upload_crypto')
            file_xor = request.files.get('file_upload_xor')
            if file_crypto and file_crypto.filename != '':
                file_input_name = 'file_upload_crypto'
            elif file_xor and file_xor.filename != '':
                file_input_name = 'file_upload_xor'
            else:
                file_input_name = None

        requires_file = tool in ['hash', 'exif', 'metadata', 'strings', 'carve', 'stego_reveal', 'pcap_analyze', 'entropy']
        if requires_file or (tool in ['base64', 'xor'] and file_input_name):
             if file_input_name and file_input_name in request.files:
                 file = request.files[file_input_name]
                 if file and file.filename != '':
                     filename = secure_filename(file.filename)
                     temp_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                     file.save(temp_path)
                     evidence_summary = f"Analysis of file: {filename}"
                 elif tool not in ['base64', 'xor']:
                     return jsonify({'error': 'No file was selected.'})
             elif tool not in ['base64', 'xor']:
                 return jsonify({'error': 'No file was uploaded.'})

        # --- Crypto Inputs ---
        input_data = None
        if tool in ['base64', 'xor']:
            text_in = request.form.get('text_input') or request.form.get('text_input_xor')
            if temp_path:
                with open(temp_path, 'rb') as f:
                    input_data = f.read()
                evidence_summary = f"Crypto analysis of file: {os.path.basename(temp_path)}"
            elif text_in:
                 input_data = text_in.encode('utf-8', errors='ignore') 
                 evidence_summary = f"Crypto analysis of text input"
            else:
                return jsonify({'error': 'No text or file provided for crypto tool.'})
        elif tool == 'rot13':
             text_in = request.form.get('text_input_rot13')
             if not text_in:
                 return jsonify({'error': 'No text provided for ROT13.'})
             input_data = text_in
             evidence_summary = "ROT13 Cipher on text input"

        # --- Tool Dispatch ---
        if tool == 'hash':
            hash_data = hash_file(temp_path)
            if 'error' in hash_data:
                result_text = hash_data['error']
            else:
                pretty_result = hash_data
                result_text = f"File: {hash_data['filename']}\nMD5: {hash_data['md5']}\nSHA-256: {hash_data['sha256']}"
                evidence_summary = f"File Hash: {os.path.basename(temp_path)}"
        elif tool == 'exif':
            result_text = get_exif_data(temp_path)
        elif tool == 'metadata':
            result_text = get_doc_metadata(temp_path)
        elif tool == 'strings':
            result_text = extract_strings(temp_path)
        elif tool == 'carve':
            result_text = carve_files(temp_path)
        elif tool == 'stego_reveal':
            result_text = stego_tool('reveal', temp_path, None)
        elif tool == 'pcap_analyze':
            result_text = analyze_pcap(temp_path)
        elif tool == 'entropy':
            result_text = calculate_entropy(temp_path)
        elif tool == 'registry':
            hive_path = request.form.get('registry_path')
            if not hive_path:
                return jsonify({'error': 'Path required for SYSTEM hive.'})
            result_text = parse_registry_usb(hive_path)
            evidence_summary = f"Registry Scan: {os.path.basename(hive_path)}"
        elif tool == 'browser':
            history_path = request.form.get('browser_path')
            result_text = parse_browser_history(history_path or None)
            evidence_summary = "Chrome History Scan"
        elif tool == 'search':
            search_dir = request.form.get('search_dir')
            search_keyword = request.form.get('search_keyword')
            if not search_dir or not search_keyword:
                return jsonify({'error': 'Dir and keyword required.'})
            result_text = keyword_search(search_dir, search_keyword)
            evidence_summary = f"Keyword Search for '{search_keyword}'"
        elif tool == 'base64':
            mode = request.form.get('base64_mode')
            result_text = base64_tool(mode, input_data)
            if not evidence_summary:
                evidence_summary = f"Base64 {mode} on text"
        elif tool == 'rot13':
            result_text = rot13_tool(input_data)
        elif tool == 'xor':
            key = request.form.get('xor_key')
            key_type = request.form.get('xor_key_type')
            if not key:
                return jsonify({'error': 'XOR key is required.'})
            result_text = xor_tool(input_data, key, key_type)
            if not evidence_summary:
                evidence_summary = f"XOR text with key '{key}'"
        else:
            return jsonify({'error': 'Selected tool is not recognized.'})

        # --- DB Persistance ---
        is_error = isinstance(result_text, str) and (result_text.lower().startswith("error:") or result_text.lower().startswith("no ") or "not found" in result_text.lower())

        if not is_error and result_text:
            db = get_db()
            cursor = db.cursor()
            cursor.execute(
                "INSERT INTO evidence (case_id, tool_used, evidence_summary, full_result) VALUES (?, ?, ?, ?)",
                (case_id, tool, evidence_summary, result_text if isinstance(result_text, str) else json.dumps(result_text))
            )
            db.commit()
            
            new_evidence_id = cursor.lastrowid
            cursor.execute("SELECT * FROM evidence WHERE evidence_id = ?", (new_evidence_id,))
            new_evidence = cursor.fetchone()
            new_evidence_dict = dict(new_evidence)
            
            if pretty_result:
                new_evidence_dict['pretty_result'] = pretty_result
                
            return jsonify({'new_evidence': new_evidence_dict})
            
        elif result_text:
             return jsonify({'error': result_text})
        else:
             return jsonify({'error': 'Tool execution failed silently.'})

    except Exception as e:
        try:
            db = get_db()
            db.rollback()
        except Exception:
            pass
        return jsonify({'error': str(e)})
        
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception as e:
                print(f"Error cleaning temp file {temp_path}: {e}")

# --- WebSocket Handlers ---

def sniff_packets_thread(case_id, sid):
    try:
        packet_count = 0
        max_packets = 20
        sniffing_logs[sid] = "--- Live Packet Sniff Log ---\n"
        socketio.sleep(0)
        
        while not stop_sniffing_event.is_set() and packet_count < max_packets:
            pkts = sniff(count=1, timeout=1, stop_filter=lambda p: stop_sniffing_event.is_set())
            
            if stop_sniffing_event.is_set():
                break
                
            if pkts:
                packet = pkts[0]
                packet_count += 1
                line = "Packet: "
                
                if IP in packet:
                    line += f"{packet[IP].src} -> {packet[IP].dst}"
                
                if TCP in packet:
                    line += f" (TCP Port: {packet[TCP].dport})"
                elif UDP in packet:
                    line += f" (UDP Port: {packet[UDP].dport})"
                    
                sniffing_logs[sid] += line + "\n"
                socketio.emit('packet_data', {'line': line}, to=sid)
            
            socketio.sleep(0.01)
            
        final_log = sniffing_logs.pop(sid, "Log data empty.")
        message = f'\n\n--- Sniffing {"complete" if not stop_sniffing_event.is_set() else "stopped by user"} ({packet_count} packets). ---'
        final_log += message
        
        with app.app_context():
            db = get_db()
            cursor = db.cursor()
            cursor.execute("INSERT INTO evidence (case_id, tool_used, evidence_summary, full_result) VALUES (?, ?, ?, ?)", 
                           (case_id, 'sniff', f'Live Sniff Log ({packet_count} packets)', final_log))
            db.commit()
            
            new_evidence_id = cursor.lastrowid
            cursor.execute("SELECT * FROM evidence WHERE evidence_id = ?", (new_evidence_id,))
            new_evidence = cursor.fetchone()
            
            socketio.emit('sniffing_stopped', {'message': message, 'new_evidence': dict(new_evidence)}, to=sid)
            
    except PermissionError:
        socketio.emit('sniffing_error', {'error': "Permission denied. Please run as Administrator/root."}, to=sid)
    except Exception as e:
        socketio.emit('sniffing_error', {'error': str(e)}, to=sid)
    finally:
        sniffing_logs.pop(sid, None)

@socketio.on('start_sniffing')
def handle_start_sniffing(data):
    global sniffer_thread
    case_id = data.get('case_id')
    if not case_id: return
    
    stop_sniffing_event.clear()
    sniffer_thread = socketio.start_background_task(target=sniff_packets_thread, case_id=case_id, sid=request.sid)

@socketio.on('stop_sniffing')
def handle_stop_sniffing(data):
    stop_sniffing_event.set()

if __name__ == "__main__":
    init_db()
    print("--- Digital Forensic Toolkit Running ---")
    print("Open browser to: http://127.0.0.1:5000")
    
    try:
        socketio.run(app, host='0.0.0.0', port=5000, debug=True)
    except Exception as e:
        if "Address already in use" in str(e):
            print("\nError: Port 5000 is busy.")
        else:
            print(f"\nError: {e}")