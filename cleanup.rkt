#lang racket

(define files-to-delete
  '("hashed.txt"
    "audit.txt"
    "audit-hash.txt"
    "audit-encrypted.txt"
    "input.txt"
    "input.csv"
    "input-decrypted.csv"
    "encrypted-input.csv"
    "decrypted.txt"
    "encrypted.txt"
    "output.csv"))

(for-each
 (lambda (file)
   (when (file-exists? file)
     (delete-file file)
     (displayln (string-append "🧹 Deleted: " file))))
 files-to-delete)

(displayln "✅ Cleanup complete.")

