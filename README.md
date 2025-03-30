# 🔐 Secure Data Normalization Pipeline for Ethical AI

This project implements a secure preprocessing pipeline to support ethical AI compliance. It includes:

- AES-256-CBC encryption of sensitive fields
- SHA-256 hashing and verification for audit logs
- Role-based data masking (column + row level)
- Data normalization and output to CSV
- Full audit trace logging

## 🧠 Technologies Used
- Racket (data logic, masking, normalization)
- Python (AES encryption, hashing, Excel parsing)

## 📁 Structure

- `normalize-and-encrypt.rkt` — main Racket pipeline
- `crypto.py` — Python encryption/decryption/hash module
- `cleanup.rkt` — deletes temp files
- `input.xlsx` — example input
- `output.csv` — normalized result

## ⚖️ Compliance
- Follows principles from NIST RMF
- Aligned with HIPAA, GDPR (minimization, traceability)

---

## 📸 Poster
[Link or screenshot image can be added here if hosted]

