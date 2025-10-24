import os
import sqlite3
import json
import io
import uuid
from datetime import datetime, timedelta
import socket
import struct
import traceback
import numpy as np
import cv2
from PIL import Image
import dlib

# ---------------------------------------------------------------------
# GLOBAL CONFIGURATION AND CONSTANTS
# ---------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "applications.db")   # SQLite database
ALERT_LOG = os.path.join(BASE_DIR, "alerts.log")      # Text-based alert log
ALERT_JSON = os.path.join(BASE_DIR, "alerts.json")    # JSON-based alert log
UPLOADS_DIR = os.path.join(BASE_DIR, "uploads")       # Folder to save uploaded photos

os.makedirs(UPLOADS_DIR, exist_ok=True)

# Thresholds for matching and duplicate detection
EMBED_MATCH_THRESH = 0.5           # Euclidean distance threshold for face embeddings
HASH_HAMMING_THRESH = 4            # Max Hamming distance for image hash match

# Submission control parameters (anti-spam / anomaly detection)
SUBMISSION_WINDOW_MINUTES = 10
MAX_SUBMISSIONS_PER_DEVICE = 5
MAX_SUBMISSIONS_PER_SUBNET = 15

# Dlib model paths
SHAPE_PREDICTOR = os.path.join(BASE_DIR, "shape_predictor_68_face_landmarks.dat")
FACE_RECOG_MODEL = os.path.join(BASE_DIR, "fr_model.dat")

# ---------------------------------------------------------------------
# MODEL VERIFICATION AND INITIALIZATION
# ---------------------------------------------------------------------

_missing_models = []
if not os.path.exists(SHAPE_PREDICTOR):
    _missing_models.append(SHAPE_PREDICTOR)
if not os.path.exists(FACE_RECOG_MODEL):
    _missing_models.append(FACE_RECOG_MODEL)

if _missing_models:
    print("WARNING: missing dlib model(s):", _missing_models)

_detector = None
_pose_predictor = None
_face_encoder = None

def _ensure_dlib_models():
    """
    Lazy loads dlib's required models (face detector, shape predictor, and face encoder)
    Ensures they are loaded once per runtime to improve efficiency.
    """
    global _detector, _pose_predictor, _face_encoder
    if _detector is None:
        if not os.path.exists(SHAPE_PREDICTOR) or not os.path.exists(FACE_RECOG_MODEL):
            raise FileNotFoundError(
                "Required dlib model(s) not found. Place shape_predictor_68_face_landmarks.dat "
                "and dlib_face_recognition_resnet_model_v1.dat in the script folder."
            )
        _pose_predictor = dlib.shape_predictor(SHAPE_PREDICTOR)
        _face_encoder = dlib.face_recognition_model_v1(FACE_RECOG_MODEL)
        _detector = dlib.get_frontal_face_detector()
    return _detector, _pose_predictor, _face_encoder


# ---------------------------------------------------------------------
# DATABASE INITIALIZATION AND HELPERS
# ---------------------------------------------------------------------

def init_db(db_path=DB_PATH):
    """
    Creates required SQLite tables if they do not already exist.
    Tables:
      - applications: stores user application info + embeddings
      - submissions: tracks submission metadata for time-series analysis
      - alerts: logs detected anomalies/duplicate cases
    """
    con = sqlite3.connect(db_path)
    c = con.cursor()

    # Applications table stores all applicant info
    c.execute('''
        CREATE TABLE IF NOT EXISTS applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT,
            aadhaar_number TEXT,
            gender TEXT,
            dob TEXT,
            age INTEGER,
            father_name TEXT,
            marital_status TEXT,
            address TEXT,
            contact_number TEXT,
            device_id TEXT,
            ip_address TEXT,
            subnet TEXT,
            photo_path TEXT,
            img_hash TEXT,
            embedding BLOB,
            timestamp TEXT
        )
    ''')

    # Submissions table tracks submission activity for anomaly detection
    c.execute('''
        CREATE TABLE IF NOT EXISTS submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            app_id INTEGER,
            timestamp TEXT,
            device_id TEXT,
            ip_address TEXT,
            subnet TEXT
        )
    ''')

    # Alerts table stores flagged duplicate or anomaly events
    c.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            alert_type TEXT,
            description TEXT,
            details TEXT
        )
    ''')
    con.commit()
    con.close()


# ---------------------------------------------------------------------
# IMAGE AND EMBEDDING UTILITIES
# ---------------------------------------------------------------------

def save_embedding_to_blob(embedding: np.ndarray):
    """Converts a NumPy face embedding array to a SQLite BLOB for storage."""
    memfile = io.BytesIO()
    np.save(memfile, embedding)
    memfile.seek(0)
    return sqlite3.Binary(memfile.read())

def load_embedding_from_blob(blob) -> np.ndarray:
    """Reconstructs a NumPy array from a SQLite BLOB."""
    memfile = io.BytesIO(blob)
    memfile.seek(0)
    return np.load(memfile)

def average_hash(pil_img: Image.Image, hash_size=8):
    """
    Computes the perceptual 'average hash' (aHash) of an image.
    Used to detect visually identical or near-identical photos.
    """
    img = pil_img.convert("L").resize((hash_size, hash_size), Image.Resampling.LANCZOS)
    pixels = np.array(img).flatten()
    avg = pixels.mean()
    diff = pixels > avg
    bit_string = ''.join('1' if v else '0' for v in diff)
    hex_string = '{:0{}x}'.format(int(bit_string, 2), hash_size * hash_size // 4)
    return hex_string

def hamming_distance_hash(h1: str, h2: str):
    """Computes Hamming distance between two hexadecimal image hashes."""
    b1 = bin(int(h1, 16))[2:].zfill(len(h1) * 4)
    b2 = bin(int(h2, 16))[2:].zfill(len(h2) * 4)
    return sum(ch1 != ch2 for ch1, ch2 in zip(b1, b2))

def ip_to_subnet(ip, mask_bits=24):
    """
    Converts an IP address to subnet string (e.g., 192.168.1.0/24)
    Used for grouping submissions by network origin.
    """
    try:
        packed_ip = struct.unpack("!I", socket.inet_aton(ip))[0]
        mask = (~0) << (32 - mask_bits) & 0xffffffff
        subnet = packed_ip & mask
        subnet_str = socket.inet_ntoa(struct.pack("!I", subnet))
        return f"{subnet_str}/{mask_bits}"
    except Exception:
        return "unknown"


# ---------------------------------------------------------------------
# FACE EMBEDDING COMPUTATION
# ---------------------------------------------------------------------

def compute_face_embedding_from_bgr(img_bgr):
    """
    Extracts a 128D dlib face embedding from a given BGR image.
    Returns None if no face is detected.
    """
    detector, pose_predictor, face_encoder = _ensure_dlib_models()
    rgb = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2RGB)
    dets = detector(rgb, 1)
    if len(dets) == 0:
        return None
    # Select the largest face (in case of multiple)
    areas = [(d.right() - d.left()) * (d.bottom() - d.top()) for d in dets]
    idx = int(np.argmax(areas))
    d = dets[idx]
    shape = pose_predictor(rgb, d)
    face_chip = dlib.get_face_chip(rgb, shape, size=150)
    descriptor = np.array(face_encoder.compute_face_descriptor(face_chip))
    return descriptor


# ---------------------------------------------------------------------
# DUPLICATE DETECTION: EMBEDDING & IMAGE HASH MATCHING
# ---------------------------------------------------------------------

def find_similar_embeddings(embedding, db_path=DB_PATH, thresh=EMBED_MATCH_THRESH):
    """
    Finds existing applications whose face embeddings are within threshold distance.
    Returns a list of matched entries (potential duplicates).
    """
    con = sqlite3.connect(db_path)
    c = con.cursor()
    c.execute("""
        SELECT id, name, email, dob, father_name, device_id, ip_address, embedding, timestamp
        FROM applications
    """)
    matches = []
    for row in c.fetchall():
        try:
            app_id, name, email, dob, father_name, device_id, ip_address, emb_blob, ts = row
            if emb_blob is None:
                continue
            emb_saved = load_embedding_from_blob(emb_blob)
            dist = float(np.linalg.norm(emb_saved - embedding))
            print('Euclidean Distance:', dist)
            if dist < thresh:
                matches.append({
                    "app_id": app_id,
                    "name": name,
                    "email": email,
                    "aadhaar_number": aadhaar_number,
                    "dob": dob,
                    "father_name": father_name,
                    "device_id": device_id,
                    "ip_address": ip_address,
                    "distance": dist,
                    "timestamp": ts
                })
        except Exception:
            continue
    con.close()
    print('ED matches: ', matches)
    return matches

def find_similar_image_hash(img_hash, db_path=DB_PATH, ham_thresh=HASH_HAMMING_THRESH):
    """
    Finds visually similar (potential duplicate) photos based on image hash comparison.
    """
    con = sqlite3.connect(db_path)
    c = con.cursor()
    c.execute("SELECT id, name, email, photo_path, img_hash, timestamp FROM applications")
    matches = []
    for row in c.fetchall():
        app_id, name, email, photo_path, h, ts = row
        if h is None:
            continue
        try:
            hd = hamming_distance_hash(h, img_hash)
            print('Hamming Distance:', hd)
            if hd <= ham_thresh:
                matches.append({
                    "app_id": app_id,
                    "name": name,
                    "email": email,
                    "photo_path": photo_path,
                    "hamming": int(hd),
                    "timestamp": ts
                })
        except Exception:
            continue
    con.close()
    print('HD matches: ', matches)
    return matches


# ---------------------------------------------------------------------
# ALERT MANAGEMENT
# ---------------------------------------------------------------------

def log_alert(alert_type: str, description: str, details: dict):
    """
    Logs an alert event to text file, JSON lines, and database.
    Used for flagging duplicates, anomalies, and suspicious submissions.
    """
    ts = datetime.utcnow().isoformat()
    entry = {"timestamp": ts, "alert_type": alert_type, "description": description, "details": details}
    try:
        with open(ALERT_JSON, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass
    with open(ALERT_LOG, "a") as f:
        f.write(f"[{ts}] {alert_type}: {description} -> {json.dumps(details)}\n")

    con = sqlite3.connect(DB_PATH)
    c = con.cursor()
    try:
        c.execute("INSERT INTO alerts (timestamp, alert_type, description, details) VALUES (?, ?, ?, ?)",
                  (ts, alert_type, description, json.dumps(details)))
        con.commit()
    except Exception:
        pass
    finally:
        con.close()
    print("ALERT:", alert_type, description, details)

# ---------------------------------------------------------------------
# APPLICATION REGISTRATION
# ---------------------------------------------------------------------
#Stores a new applicant record + submission metadata into the database.
def register_application_to_db(name, email, aadhaar_number, gender, dob, age, father_name,
                               marital_status, address, contact_number,
                               device_id, ip_address, stored_photo_path,
                               img_hash, embedding):
							   						   
    con = sqlite3.connect(DB_PATH)
    c = con.cursor()
    ts = datetime.utcnow().isoformat()
    subnet = ip_to_subnet(ip_address)
    emb_blob = save_embedding_to_blob(embedding) if embedding is not None else None
    c.execute('''
        INSERT INTO applications
        (name, email, aadhaar_number, gender, dob, age, father_name, marital_status, address, contact_number,
         device_id, ip_address, subnet, photo_path, img_hash, embedding, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (name, email, aadhaar_number, gender, dob, age, father_name, marital_status, address, contact_number,
          device_id, ip_address, subnet, stored_photo_path, img_hash, emb_blob, ts))
    app_id = c.lastrowid
    c.execute('''
        INSERT INTO submissions (app_id, timestamp, device_id, ip_address, subnet)
        VALUES (?, ?, ?, ?, ?)
    ''', (app_id, ts, device_id, ip_address, subnet))
    con.commit()
    con.close()
    return app_id


def count_submissions_in_window(device_id=None, subnet=None, window_minutes=SUBMISSION_WINDOW_MINUTES, db_path=DB_PATH):
    con = sqlite3.connect(db_path)
    c = con.cursor()
    cutoff = (datetime.utcnow() - timedelta(minutes=window_minutes)).isoformat()
    if device_id:
        c.execute("SELECT COUNT(*) FROM submissions WHERE device_id=? AND timestamp>=?", (device_id, cutoff))
    elif subnet:
        c.execute("SELECT COUNT(*) FROM submissions WHERE subnet=? AND timestamp>=?", (subnet, cutoff))
    else:
        c.execute("SELECT COUNT(*) FROM submissions WHERE timestamp>=?", (cutoff,))
    cnt = c.fetchone()[0]
    con.close()
    return cnt

# ---------------------------------------------------------------------
# TIME SERIES ANOMALY DETECTION
# ---------------------------------------------------------------------
"""
    Checks whether too many submissions have been made within the time window.
    Triggers alerts for:
      - DEVICE_SUBMISSION_BURST (too many from one device)
      - SUBNET_SUBMISSION_BURST (too many from same subnet)
"""
def detect_time_series_anomalies(device_id, ip_address):
    subnet = ip_to_subnet(ip_address)
    device_count = count_submissions_in_window(device_id=device_id)
    subnet_count = count_submissions_in_window(subnet=subnet)
    alerts = []
    if device_count > MAX_SUBMISSIONS_PER_DEVICE:
        desc = f"High submissions from device within {SUBMISSION_WINDOW_MINUTES} minutes: {device_count}"
        details = {"device_id": device_id, "count": device_count}
        log_alert("DEVICE_SUBMISSION_BURST", desc, details)
        alerts.append(("DEVICE_SUBMISSION_BURST", desc, details))
    if subnet_count > MAX_SUBMISSIONS_PER_SUBNET:
        desc = f"High submissions from subnet {subnet} within {SUBMISSION_WINDOW_MINUTES} minutes: {subnet_count}"
        details = {"subnet": subnet, "count": subnet_count}
        log_alert("SUBNET_SUBMISSION_BURST", desc, details)
        alerts.append(("SUBNET_SUBMISSION_BURST", desc, details))
    return alerts

# ---------------------------------------------------------------------
# APPLICATION SUBMISSION PIPELINE
# ---------------------------------------------------------------------
"""
    Main submission pipeline:
      1. Validates and saves uploaded image
      2. Computes hash & face embedding
      3. Checks for duplicate photo, face, Aadhaar, and credentials
      4. Registers new record if clean
      5. Detects submission anomalies (burst)
    Returns a structured status dict.
"""
def submit_application(photo_path, name, email, aadhaar_number, gender, dob, age, father_name,
                       marital_status, address, contact_number, device_id, ip_address):
	
    try:
        if not os.path.exists(photo_path):
            return {"status": "error", "message": "photo not found"}

        ext = os.path.splitext(photo_path)[1].lower()
        unique_name = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:8]}{ext}"
        stored_path = os.path.join(UPLOADS_DIR, unique_name)
        try:
            with open(photo_path, "rb") as src, open(stored_path, "wb") as dst:
                dst.write(src.read())
        except Exception as e:
            img = cv2.imread(photo_path)
            if img is None:
                return {"status": "error", "message": f"could not read uploaded image: {e}"}
            cv2.imwrite(stored_path, img)

        pil = Image.open(stored_path).convert("RGB")
        img_hash = average_hash(pil)

        img_bgr = cv2.cvtColor(np.array(pil), cv2.COLOR_RGB2BGR)
        try:
            embedding = compute_face_embedding_from_bgr(img_bgr)
        except FileNotFoundError as e:
            return {"status": "error", "message": str(e)}
        except Exception as e:
            traceback.print_exc()
            return {"status": "error", "message": f"error computing embedding: {e}"}

        if embedding is None:
            return {"status": "error", "message": "no face detected in photo"}

        identical_photos = find_similar_image_hash(img_hash)
        if len(identical_photos) > 0:
            desc = "Photo duplicate detected"
            details = {"matches": identical_photos, "incoming_email": email}
            log_alert("PHOTO_DUPLICATE", desc, details)
            return {"status": "flagged", "reason": "photo_duplicate", "details": identical_photos}

        matches = find_similar_embeddings(embedding)
        if len(matches) > 0:
            for m in matches:
                if m['email'].lower() != email.lower() and m['name'].lower() == name.lower() and m['father_name'].lower() == father_name.lower() and m['dob'].lower() == dob.lower():
                    desc = "Biometric duplicate detected (same face and person, different email)"
                    details = {"match": m,
                            "incoming": {"email": email, "name": name, "device_id": device_id, "ip": ip_address}}
                    log_alert("BIOMETRIC_DUPLICATE", desc, details)
                    return {"status": "flagged", "reason": "biometric_duplicate", "details": details}
                    
                if m['email'].lower() == email.lower():    
                    desc = "Application already submitted from same mail ID!"
                    details = {"match": m,
                               "incoming": {"email": email, "name": name, "device_id": device_id, "ip": ip_address}}
                    log_alert("APPLICATION EMAIL_ID DUPLICATE", desc, details)
                    return {"status": "flagged", "reason": "email id_duplicate", "details": details}
                    
                if m['aadhaar_number'].lower() != aadhaar_number.lower() or m['aadhaar_number'].lower() != aadhaar_number.lower():    
                    desc = "Aadhar Number is different but similar face found in existing submissions!"
                    details = {"match": m,
                               "incoming": {"email": email, "name": name, "device_id": device_id, "ip": ip_address}}
                    log_alert("AADHAAR NUMBER DIFFERENT BUT SIMILAR FACE FOUND", desc, details)
                    return {"status": "flagged", "reason": "similar face_duplicate", "details": details}
                                      

        con = sqlite3.connect(DB_PATH)
        c = con.cursor()
        c.execute('''
            SELECT id, name, email, aadhaar_number, gender, dob, age, father_name, marital_status,
                   address, contact_number, device_id, ip_address, timestamp
            FROM applications
            WHERE LOWER(name)=? AND LOWER(email)=? AND dob=? AND LOWER(father_name)=?
        ''', (name.lower(), email.lower(), dob, father_name.lower()))
        existing_submissions = [
            {
                "app_id": row[0],
                "name": row[1],
                "email": row[2],
                "aadhaar_number": row[3],
                "gender": row[4],
                "dob": row[5],
                "age": row[6],
                "father_name": row[7],
                "marital_status": row[8],
                "address": row[9],
                "contact_number": row[10],
                "device_id": row[11],
                "ip_address": row[12],
                "timestamp": row[13]
            }
            for row in c.fetchall()
        ]
        con.close()

        if existing_submissions:
            desc = "Duplicate application detected (same credentials already submitted)"
            details = {
                "existing": existing_submissions,
                "incoming": {
                    "name": name,
                    "email": email,
                    "aadhaar_number": aadhaar_number,
                    "dob": dob,
                    "father_name": father_name,
                    "contact_number": contact_number,
                    "device_id": device_id,
                    "ip": ip_address
                }
            }
            log_alert("CREDENTIAL_DUPLICATE", desc, details)
            return {
                "status": "flagged",
                "reason": "credential_duplicate",
                "details": details
            }
            
        con = sqlite3.connect(DB_PATH)
        c = con.cursor()
        c.execute("SELECT id, name, email FROM applications WHERE aadhaar_number=?", (aadhaar_number,))
        existing = c.fetchall()
        con.close()

        if existing:
            desc = "Duplicate application detected (same Aadhaar number)"
            details = {"existing": existing, "incoming_aadhaar": aadhaar_number}
            log_alert("AADHAAR_DUPLICATE", desc, details)
            return {"status": "flagged", "reason": "aadhaar_duplicate", "details": details}
            
            
        app_id = register_application_to_db(name, email, aadhaar_number, gender, dob, age, father_name,
                                        marital_status, address, contact_number,
                                        device_id, ip_address, stored_path, img_hash, embedding)

        alerts = detect_time_series_anomalies(device_id, ip_address)

        return {"status": "accepted", "app_id": app_id, "alerts": alerts}

    except Exception as e:
        traceback.print_exc()
        return {"status": "error", "message": str(e)}

# ---------------------------------------------------------------------
# ALERT SUMMARY EXPORT
# ---------------------------------------------------------------------
"""
    Exports the 200 most recent alerts into a single summarized JSON file.
    Used for dashboard or visualization.
"""
def generate_alert_summary_json(out_path=None):
    out_path = out_path or os.path.join(BASE_DIR, "alert_summary.json")
    con = sqlite3.connect(DB_PATH)
    c = con.cursor()
    c.execute("SELECT timestamp, alert_type, description, details FROM alerts ORDER BY id DESC LIMIT 200")
    rows = c.fetchall()
    con.close()
    arr = []
    for (ts, atype, desc, details) in rows:
        try:
            det = json.loads(details)
        except Exception:
            det = details
        arr.append({"timestamp": ts, "type": atype, "desc": desc, "details": det})
    with open(out_path, "w") as f:
        json.dump({"generated_at": datetime.utcnow().isoformat(), "alerts": arr}, f, indent=2)
    return out_path

# ---------------------------------------------------------------------
# AUTO INITIALIZE DATABASE ON IMPORT
# ---------------------------------------------------------------------

init_db()
