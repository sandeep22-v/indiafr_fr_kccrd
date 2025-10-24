IndiaAI Face Authentication Challenge – Application De-duplication System

#Submission for
#IndiaAI Face Authentication Challenge 2025
#Theme: AI for Application De-duplication
#By Team KCC R&D

#1 Brief Summary

This project is a prototype developed for the IndiaAI Face Authentication Challenge, focusing on AI-based de-duplication of exam, job, or service applications using facial recognition along with Aadhaar validation and credential data matching.

The system identifies duplicate applications by performing a one-to-many facial recognition search. As a secondary verification layer, the system also cross-checks applicant details (such as name, Aadhaar, date of birth etc) to ensure each applicant is uniquely registered, thereby eliminating duplicate or fraudulent submissions.

The system consists of the following components : 
1. GUI - based on Tkintder - as application interface where applications can be submitted by entering applicant details(Name, Address, Aadhar etc) and Passport size photo.

2. Face Recognition backend - using custom tuned dlib - which can detect and flag applicants who file different credentials with similar photos to dupe the system.

3. SQLite Based Storage - For Duplication check using credential datas entered by applicants.

4. Aadhar Checksum Validation using Verhoeff Algorithm - To verify the authenticity of entered Aadhar details without relying on NIC database.




#2 Folder Structure

indiaai_fr/
│
├── app_gui1.py                  # GUI frontend using Tkinter library
├── backend.py                   # Face recognition + Aadhar Checksum + Credential Match + Database logic
├── fr_model.dat                 # Dlib face recognition model
├── shape_predictor_68_face_landmarks.dat  # Landmark detector
├── samples/                     # Example applicant images
├── requirements.txt
└── README.md




#3 Unique Features of the Proposed Solution

1. One-to-Many Facial Matching using custom tuned dlib model.
2. Aadhaar validation using Verhoeff checksum
3. Device ID and IP tracking for security
4. Flagging of duplicate submissions at submission stage itself in real time without latency
5. Local SQLite database to store applicant details






 #4 Installation

1. Clone the repository
git clone https://github.com/<your-username>/indiaai_fr.git

From command prompt/terminal,go to indiaai_fr folder,
cd indiaai_fr/

2. Install dependencies using requirements.txt file

pip3 install -r requirements.txt


3. Run the GUI/Application interface

python app_gui1.py


3.1 Fill in all required fields (Name, Aadhaar, DOB, Contact, etc.).
3.2 Upload a face image (JPG/PNG).
3.3 Click “Submit Application”.

The system will:

Validate Aadhaar using Verhoeff checksum

Extract facial embeddings and recognise using one to many facial recognition

Compare against the database

Save or flag(reject) the record


If application is accepted: The GUI will give a pop-up stating 'Application Accepted,App ID : '
If application is rejected: The GUI will give a pop-up stating 'Duplicate Detected'


#5 Authors

Team KCC R&D Members
1. Dr. Revathy Sivanandan, Senior Engineer, Kerala State Electronics Development Corporation Limited
2. Mr. Sandeep Vivek, Senior Engineer, Kerala State Electronics Development Corporation Limited

Note : All data including images and embeddings is stored locally in SQLite for demonstration and evaluation purposes only.
