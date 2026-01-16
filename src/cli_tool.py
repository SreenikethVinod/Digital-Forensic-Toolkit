import argparse
import os
import hashlib
import sqlite3
import re
import platform
from datetime import datetime, timedelta

# Third-party imports with installation hints
try:
    from PIL import Image, ExifTags
    from scapy.all import sniff, wrpcap, rdpcap, DNSQR
    import PyPDF2
    import docx
    from Registry import Registry
    from stegano import lsb
except ImportError as e:
    print(f"Missing dependency: {e}. Please install: scapy Pillow PyPDF2 python-docx python-registry stegano")
    exit()

def print_header(title):
    """Prints a formatted header for output sections."""
    print("\n" + "="*60)
    print(f"--- {title} ---")
    print("="*60)

# --- Core Forensic Functions ---

def hash_file(file_path):
    print_header(f"Hashing File: {os.path.basename(file_path)}")
    if not os.path.exists(file_path):
        print(f"Error: File not found at '{file_path}'")
        return

    hasher_md5 = hashlib.md5()
    hasher_sha256 = hashlib.sha256()
    
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher_md5.update(chunk)
            hasher_sha256.update(chunk)
            
    print(f"MD5 Hash:    {hasher_md5.hexdigest()}")
    print(f"SHA-256 Hash: {hasher_sha256.hexdigest()}")

def get_exif_data(image_path):
    print_header(f"EXIF Metadata for: {os.path.basename(image_path)}")
    if not os.path.exists(image_path):
        print(f"Error: Image not found at '{image_path}'")
        return

    try:
        image = Image.open(image_path)
        exif_data = image._getexif()
        if not exif_data:
            print("No EXIF metadata found.")
            return

        for tag_id, value in exif_data.items():
            tag_name = ExifTags.TAGS.get(tag_id, tag_id)
            if isinstance(value, bytes):
                value = value.decode('utf-8', errors='ignore')
            print(f"{str(tag_name):<25}: {str(value)}")
    except Exception as e:
        print(f"An error occurred: {e}")

def start_sniffer(interface, count):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_filename = f"capture_{timestamp}.pcap"
    
    print_header(f"Starting Network Packet Sniffer ({count} packets)")
    try:
        packets = sniff(iface=interface, count=count, store=True)
        wrpcap(output_filename, packets)
        print(f"Capture complete. Saved to '{output_filename}'")
    except Exception as e:
        print(f"An error occurred: {e}")
        print("(Hint: This tool usually requires root/Administrator privileges.)")

def analyze_pcap(pcap_path):
    print_header(f"Analyzing Pcap File: {os.path.basename(pcap_path)}")
    if not os.path.exists(pcap_path):
        print(f"Error: Pcap file not found at '{pcap_path}'")
        return

    packets = rdpcap(pcap_path)
    dns_queries = []
    
    for packet in packets:
        if packet.haslayer(DNSQR):
            dns_queries.append(packet[DNSQR].qname.decode())
            
    print(f"\n--- Found {len(set(dns_queries))} unique DNS Queries ---")
    for query in sorted(list(set(dns_queries))):
        print(f"  - {query}")

def extract_strings(file_path):
    print_header(f"Extracting Strings from: {os.path.basename(file_path)}")
    if not os.path.exists(file_path):
        print(f"Error: File not found at '{file_path}'")
        return

    with open(file_path, 'rb') as f:
        content = f.read()
        
    strings = re.findall(b"[\x20-\x7E]{4,}", content)
    print(f"Found {len(strings)} strings (4+ characters):\n")
    for s in strings:
        print(s.decode('ascii', errors='ignore'))

def get_doc_metadata(doc_path):
    print_header(f"Document Metadata for: {os.path.basename(doc_path)}")
    if not os.path.exists(doc_path):
        print(f"Error: Document not found at '{doc_path}'")
        return

    if doc_path.lower().endswith('.pdf'):
        with open(doc_path, 'rb') as f:
            reader = PyPDF2.PdfReader(f)
            for key, value in reader.metadata.items():
                print(f"{key[1:]:<20}: {value}")
                
    elif doc_path.lower().endswith('.docx'):
        props = docx.Document(doc_path).core_properties
        for p in dir(props):
            if not p.startswith('_'):
                try:
                    value = getattr(props, p)
                    if value:
                        print(f"{p:<20}: {value}")
                except Exception:
                    pass

def parse_browser_history(history_path):
    # Auto-detect path if not provided
    if not history_path:
        system = platform.system()
        user_home = os.path.expanduser('~')
        if system == 'Windows':
            history_path = os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default', 'History')
        elif system == 'Darwin':
            history_path = os.path.join(user_home, 'Library', 'Application Support', 'Google', 'Chrome', 'Default', 'History')
        elif system == 'Linux':
            history_path = os.path.join(user_home, '.config', 'google-chrome', 'Default', 'History')

    print_header(f"Parsing Browser History: {history_path}")
    if not history_path or not os.path.exists(history_path):
        print(f"Error: History file not found at '{history_path}'")
        return

    try:
        # Connect to SQLite DB
        con = sqlite3.connect(history_path)
        cur = con.cursor()
        cur.execute("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 20")
        
        for row in cur.fetchall():
            # Chrome timestamp is microseconds since Jan 1, 1601
            ts = datetime(1601, 1, 1) + timedelta(microseconds=row[3])
            print(f"\nURL: {row[0]}")
            print(f"Title: {row[1]}")
            print(f"Last Visit: {ts.strftime('%Y-%m-%d %H:%M:%S')}")
            
        con.close()
    except sqlite3.OperationalError:
        print("Error: Database is locked. Please close Google Chrome and try again.")
    except Exception as e:
        print(f"Error: {e}")

def keyword_search(directory, keyword):
    print_header(f"Searching for '{keyword}' in '{directory}'")
    if not os.path.isdir(directory):
        print(f"Error: Directory not found at '{directory}'")
        return

    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    if keyword in f.read():
                        print(f"[+] Found in: {file_path}")
            except (IOError, OSError):
                continue

def carve_files(data_file):
    print_header(f"Carving JPEGs from: {os.path.basename(data_file)}")
    if not os.path.exists(data_file):
        print(f"Error: Data file not found at '{data_file}'")
        return

    jpeg_header = b'\xff\xd8'
    jpeg_footer = b'\xff\xd9'
    
    try:
        with open(data_file, 'rb') as f:
            data = f.read()
            
        start_indices = [m.start() for m in re.finditer(re.escape(jpeg_header), data)]
        if not start_indices:
            print("No JPEG headers found in the file.")
            return
        
        found_images = 0
        for start_index in start_indices:
            footer_index = data.find(jpeg_footer, start_index)
            if footer_index != -1:
                end_index = footer_index + 2
                image_data = data[start_index:end_index]
                
                output_filename = f"carved_image_{found_images}_{start_index}.jpg"
                with open(output_filename, 'wb') as img_file:
                    img_file.write(image_data)
                    
                print(f"[+] Found and carved image: {output_filename} (Size: {len(image_data)} bytes)")
                found_images += 1
                
        print(f"\nCarving complete. Found a total of {found_images} potential JPEG images.")
    except Exception as e:
        print(f"An error occurred during carving: {e}")

def parse_registry_usb(registry_hive):
    print_header(f"Parsing USB History from Registry Hive: {os.path.basename(registry_hive)}")
    if platform.system() != "Windows":
        print("Error: This feature is for Windows only.")
        return
    if not os.path.exists(registry_hive):
        print(f"Error: Registry hive not found at '{registry_hive}'")
        return

    try:
        reg = Registry.Registry(registry_hive)
        key = reg.open(r"ControlSet001\Enum\USBSTOR")
        
        print(f"--- Found {key.number_of_subkeys()} USB Storage Device Entries ---")
        for subkey in key.subkeys():
            print(f"\n[+] Device: {subkey.name()}")
            for device_id_key in subkey.subkeys():
                print(f"  - Serial Number: {device_id_key.name()}")
                try:
                    friendly = device_id_key.value('FriendlyName').value()
                    print(f"    - Friendly Name: {friendly}")
                except Exception:
                    pass
                print(f"    - Last Connected: {device_id_key.timestamp()}")
    except Exception as e:
        print(f"Registry Error: {e}")
        print("Hint: Run as Administrator and ensure you are reading a valid SYSTEM hive.")

def stego_tool(mode, image_path, message, output_path):
    print_header(f"Steganography Tool (Mode: {mode})")
    if not os.path.exists(image_path):
        print(f"Error: Image file not found at '{image_path}'")
        return

    try:
        if mode == 'hide':
            if not message or not output_path:
                print("Error: 'hide' mode requires -sm/--secretmessage and -o/--output")
                return
            print(f"Hiding message in '{os.path.basename(image_path)}'...")
            secret_image = lsb.hide(image_path, message)
            secret_image.save(output_path)
            print(f"Message successfully hidden in '{output_path}'")

        elif mode == 'reveal':
            print(f"Revealing message from '{os.path.basename(image_path)}'...")
            secret_text = lsb.reveal(image_path)
            if secret_text:
                print("\n--- SECRET MESSAGE FOUND ---")
                print(secret_text)
                print("--------------------------")
            else:
                print("No secret message found in this image.")
    except Exception as e:
        print(f"Stego Error: {e}")

# --- Main Execution ---

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Digital Forensic Toolkit (CLI)",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # Tool choices
    parser.add_argument("tool", choices=[
        'hash', 'exif', 'sniff', 'pcap_analyze', 'strings', 'metadata', 'browser', 'search',
        'carve', 'registry', 'stego'],
        help="Select the forensic tool to run."
    )

    # Universal arguments
    parser.add_argument("-f", "--file", dest="file_path", help="Path to input file.")
    
    # Specific arguments
    parser.add_argument("-if", "--interface", dest="interface", help="Network interface for sniffing.")
    parser.add_argument("-c", "--count", dest="packet_count", type=int, default=20, help="Packet count.")
    parser.add_argument("-p", "--pcapfile", dest="pcap_path", help="Path to .pcap file.")
    parser.add_argument("-hp", "--historypath", dest="history_path", help="Path to Chrome History file.")
    parser.add_argument("-d", "--directory", dest="directory", help="Directory to search.")
    parser.add_argument("-k", "--keyword", dest="keyword", help="Keyword to search for.")
    parser.add_argument("-rh", "--reghive", dest="registry_hive", help="Path to Windows SYSTEM registry hive.")
    
    # Stego arguments
    parser.add_argument("-m", "--mode", dest="stego_mode", choices=['hide', 'reveal'], help="Stego mode.")
    parser.add_argument("-i", "--image", dest="image_path", help="Input image for Stego.")
    parser.add_argument("-sm", "--secretmessage", dest="secret_message", help="Message to hide.")
    parser.add_argument("-o", "--output", dest="output_path", help="Output path for hidden image.")

    args = parser.parse_args()

    # --- Tool Routing ---
    
    # Validation for tools requiring a generic file
    if args.tool in ['hash', 'exif', 'strings', 'metadata', 'carve'] and not args.file_path:
        parser.error(f"The '{args.tool}' tool requires the -f/--file argument.")
    
    # Execution
    if args.tool == 'hash':
        hash_file(args.file_path)
    elif args.tool == 'exif':
        get_exif_data(args.file_path)
    elif args.tool == 'sniff':
        if not args.interface:
            print("Note: No interface specified (-if). Scapy will guess the default interface.")
        start_sniffer(args.interface, args.packet_count)
    elif args.tool == 'pcap_analyze':
        if not args.pcap_path: parser.error("'pcap_analyze' requires -p/--pcapfile")
        analyze_pcap(args.pcap_path)
    elif args.tool == 'strings':
        extract_strings(args.file_path)
    elif args.tool == 'metadata':
        get_doc_metadata(args.file_path)
    elif args.tool == 'browser':
        parse_browser_history(args.history_path)
    elif args.tool == 'search':
        if not (args.directory and args.keyword):
            parser.error("'search' requires both -d/--directory and -k/--keyword")
        keyword_search(args.directory, args.keyword)
    elif args.tool == 'carve':
        carve_files(args.file_path)
    elif args.tool == 'registry':
        if not args.registry_hive: parser.error("'registry' requires -rh/--reghive")
        parse_registry_usb(args.registry_hive)
    elif args.tool == 'stego':
        if not args.stego_mode or not args.image_path:
            parser.error("'stego' requires -m/--mode and -i/--image")
        stego_tool(args.stego_mode, args.image_path, args.secret_message, args.output_path)

if __name__ == "__main__":
    main()