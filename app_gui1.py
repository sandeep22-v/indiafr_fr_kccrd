"""
Job Application Form (Tkinter GUI)
-----------------------------------
Features:
- Aadhaar number verification using Verhoeff checksum
- Auto age calculation from Date of Birth
- Device ID and IP auto-fetch
- Photo upload with preview
- Backend integration via dup.submit_application()

Author: <Your Name>
Date: <Date>
"""

import os
import socket
import uuid
from tkinter import *
from tkinter import filedialog, messagebox
from tkcalendar import DateEntry
from PIL import Image, ImageTk
from datetime import date
import backend as dup
import requests

# ---------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------

def get_device_id():
    """
    Generate a unique device identifier by combining
    the hostname and MAC address.
    """
    mac = uuid.getnode()
    hostname = socket.gethostname()
    return f"{hostname}-{mac:x}"


def get_ip_address():
    """
    Get the local machine's IP address.
    Returns loopback (127.0.0.1) if unavailable.
    """
    try:
        return requests.get("https://api.ipify.org").text
    except Exception:
        return "127.0.0.1"

# ---------------------------------------------------------
# Aadhaar Verhoeff Checksum Validation
# ---------------------------------------------------------

def aadhaar_is_valid(num: str) -> bool:
    """
    Validate Aadhaar number using Verhoeff algorithm.

    Args:
        num (str): 12-digit Aadhaar number (numeric string)

    Returns:
        bool: True if checksum passes, else False
    """
    # Multiplication table (d-table)
    d_table = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
        [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
        [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
    ]

    # Permutation table (p-table)
    p_table = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
        [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
        [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
    ]

    # Inverse table
    inv_table = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]

    # Perform checksum validation
    c = 0
    num = num[::-1]  # Reverse the Aadhaar number
    for i, item in enumerate(num):
        c = d_table[c][p_table[i % 8][int(item)]]
    return c == 0


# ---------------------------------------------------------
# GUI Setup
# ---------------------------------------------------------

root = Tk()
root.title("Job Application Form")
root.geometry("700x900")
root.resizable(False, False)
root.configure(bg="#f2f2f2")

# ---------------------------------------------------------
# Variables
# ---------------------------------------------------------
name_var = StringVar()
email_var = StringVar()
aadhaar_var = StringVar()
device_var = StringVar(value=get_device_id())
ip_var = StringVar(value=get_ip_address())
gender_var = StringVar()
dob_var = StringVar()
age_var = StringVar()
father_var = StringVar()
marital_var = StringVar()
contact_var = StringVar()
photo_path = None

# ---------------------------------------------------------
# Header
# ---------------------------------------------------------
Label(root, text="Application Form", font=("Arial", 18, "bold"), bg="#f2f2f2").pack(pady=15)

form_frame = Frame(root, bg="#f2f2f2")
form_frame.pack(pady=10)

# ---------------------------------------------------------
# Form Fields
# ---------------------------------------------------------

# --- Full Name ---
Label(form_frame, text="Full Name:", bg="#f2f2f2", anchor="w", width=20).grid(row=0, column=0, padx=10, pady=8)
Entry(form_frame, textvariable=name_var, width=40).grid(row=0, column=1, padx=10, pady=8)

# --- Email ---
Label(form_frame, text="Email:", bg="#f2f2f2", anchor="w", width=20).grid(row=1, column=0, padx=10, pady=8)
Entry(form_frame, textvariable=email_var, width=40).grid(row=1, column=1, padx=10, pady=8)

# --- Aadhaar Number ---
Label(form_frame, text="Aadhaar Number:", bg="#f2f2f2", anchor="w", width=20).grid(row=2, column=0, padx=10, pady=8)
Entry(form_frame, textvariable=aadhaar_var, width=40).grid(row=2, column=1, padx=10, pady=8)

# --- Gender Selection ---
Label(form_frame, text="Gender:", bg="#f2f2f2", anchor="w", width=20).grid(row=3, column=0, padx=10, pady=8)
gender_menu = OptionMenu(form_frame, gender_var, "Male", "Female", "Others")
gender_menu.config(width=34)
gender_menu.grid(row=3, column=1, padx=10, pady=8)


# --- Date of Birth and Age Calculation ---
def calculate_age(*args):
    """Automatically compute age based on Date of Birth."""
    try:
        dob_str = dob_var.get()
        y, m, d = map(int, dob_str.split("-"))
        today = date.today()
        age = today.year - y - ((today.month, today.day) < (m, d))
        age_var.set(str(age))
    except Exception:
        age_var.set("")


Label(form_frame, text="Date of Birth:", bg="#f2f2f2", anchor="w", width=20).grid(row=4, column=0, padx=10, pady=8)
dob_entry = DateEntry(form_frame, textvariable=dob_var, date_pattern="yyyy-mm-dd", width=37)
dob_entry.grid(row=4, column=1, padx=10, pady=8)
dob_var.trace("w", calculate_age)  # Trigger age update on DOB change

Label(form_frame, text="Age:", bg="#f2f2f2", anchor="w", width=20).grid(row=5, column=0, padx=10, pady=8)
Entry(form_frame, textvariable=age_var, width=40, state="readonly").grid(row=5, column=1, padx=10, pady=8)

# --- Father's Name ---
Label(form_frame, text="Father's Name:", bg="#f2f2f2", anchor="w", width=20).grid(row=6, column=0, padx=10, pady=8)
Entry(form_frame, textvariable=father_var, width=40).grid(row=6, column=1, padx=10, pady=8)

# --- Marital Status ---
Label(form_frame, text="Marital Status:", bg="#f2f2f2", anchor="w", width=20).grid(row=7, column=0, padx=10, pady=8)
marital_menu = OptionMenu(form_frame, marital_var, "Married", "Unmarried", "Others")
marital_menu.config(width=34)
marital_menu.grid(row=7, column=1, padx=10, pady=8)

# --- Address ---
Label(form_frame, text="Address:", bg="#f2f2f2", anchor="w", width=20).grid(row=8, column=0, padx=10, pady=8)
address_text = Text(form_frame, width=31, height=3)
address_text.grid(row=8, column=1, padx=10, pady=8)

# --- Contact Number ---
Label(form_frame, text="Contact Number:", bg="#f2f2f2", anchor="w", width=20).grid(row=9, column=0, padx=10, pady=8)
Entry(form_frame, textvariable=contact_var, width=40).grid(row=9, column=1, padx=10, pady=8)

# --- Device Info ---
Label(form_frame, text="Device ID:", bg="#f2f2f2", anchor="w", width=20).grid(row=10, column=0, padx=10, pady=8)
Entry(form_frame, textvariable=device_var, width=40, state="readonly").grid(row=10, column=1, padx=10, pady=8)

Label(form_frame, text="IP Address:", bg="#f2f2f2", anchor="w", width=20).grid(row=11, column=0, padx=10, pady=8)
Entry(form_frame, textvariable=ip_var, width=40, state="readonly").grid(row=11, column=1, padx=10, pady=8)

# ---------------------------------------------------------
# Photo Upload Section
# ---------------------------------------------------------

img_label = Label(root, text="No image uploaded", width=30, height=10, bg="#d9d9d9", relief="ridge")
img_label.pack(pady=15)


def upload_image():
    """Allow user to upload and preview a photo."""
    global photo_path
    f = filedialog.askopenfilename(filetypes=[("Image files", "*.jpg;*.jpeg;*.png")])
    if not f:
        return
    photo_path = f
    try:
        img = Image.open(f)
        img.thumbnail((200, 200))
        tk_img = ImageTk.PhotoImage(img)
        img_label.configure(image=tk_img, text="", bg="#ffffff", width=200, height=200)
        img_label.image = tk_img
    except Exception as e:
        messagebox.showerror("Error", f"Could not open image: {e}")


Button(root, text="Upload Photo", command=upload_image, bg="#4a90e2", fg="white", width=15).pack(pady=5)

# ---------------------------------------------------------
# Form Submission Logic
# ---------------------------------------------------------

def on_submit():
    """Validate form, Aadhaar checksum, and submit application."""
    global photo_path

    # Check for missing mandatory fields
    if not all([
        name_var.get(), email_var.get(), aadhaar_var.get(),
        gender_var.get(), dob_var.get(), father_var.get(),
        marital_var.get(), contact_var.get(), photo_path
    ]):
        messagebox.showwarning("Missing Info", "Please fill all mandatory fields and upload a photo.")
        return

    # Validate Aadhaar number
    aadhaar_num = aadhaar_var.get().replace(" ", "")
    if not aadhaar_num.isdigit() or len(aadhaar_num) != 12 or not aadhaar_is_valid(aadhaar_num):
        messagebox.showwarning("Invalid Aadhaar", "Please enter a valid Aadhaar number (failed checksum).")
        return

    # Get address text
    address_val = address_text.get("1.0", "end").strip()

    # Call backend submission function
    res = dup.submit_application(
        photo_path=photo_path,
        name=name_var.get(),
        email=email_var.get(),
        aadhaar_number=aadhaar_num,
        gender=gender_var.get(),
        dob=dob_var.get(),
        age=age_var.get(),
        father_name=father_var.get(),
        marital_status=marital_var.get(),
        address=address_val,
        contact_number=contact_var.get(),
        device_id=device_var.get(),
        ip_address=ip_var.get()
    )

    # Handle backend response
    if res["status"] == "accepted":
        msg = f"✅ Application Accepted\nApp ID: {res['app_id']}"
        if res.get("alerts"):
            msg += f"\n⚠ Alerts: {len(res['alerts'])} (see alerts.json)"
        messagebox.showinfo("Success", msg)

    elif res["status"] == "flagged":
        reason = res.get("reason", "unknown")
        messagebox.showerror("Duplicate Detected", f"⚠ Application Flagged for {reason.upper()}\nSee alerts.log for details.")

    else:
        messagebox.showerror("Error", res.get("message", "Unknown error"))


Button(root, text="Submit Application", command=on_submit, bg="#28a745", fg="white", width=20).pack(pady=10)

# ---------------------------------------------------------
# Main Event Loop
# ---------------------------------------------------------
root.mainloop()
