#lang racket

;; helper function for write-to-csv
(define (write-csv-row row)
  (string-join (map (lambda (pair) (format "~a" (cdr pair))) row) ","))
 ; Only values, comma-separated

;; 🔐 Role access map
(define user-access-rules
  '((admin   ssn name salary)
    (manager name salary)
    (analyst name salary)
    (viewer  name)))

;; 🔐 User database: (username, hashed-password, role)
(define users
  (list
    (list "admin"   "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8" 'admin)
    (list "viewer1" "8d969eef6ecad3c29a3a629280e686cff8fabf9fe9389515c9e4e7c912f0d3cb" 'viewer)
    (list "analyst" "12dea96fec20593566ab75692c9949596833adc9" 'analyst)))

;; 📝 Global audit log storage
(define audit-log '())

;; 🔐 Use Python to hash password string with SHA-256
(define (hash-password str)
  (define cmd-str (string-append "python crypto.py hash-string \"" str "\" hashed.txt"))
  (define success? (system cmd-str))
  (if (not success?)
      (begin
        (displayln "❌ Python command failed.")
        "")
      (with-handlers ([exn:fail:filesystem?
                       (lambda (e)
                         (displayln "❌ Failed to read hashed.txt")
                         "")])
        (call-with-input-file "hashed.txt"
          (lambda (in)
            (define result (string-trim (port->string in)))
            (displayln (format "🔐 Hash from Python: ~a" result))
            result)))))

;; 🔐 Prompt user for login, return role if authenticated
(define (login)
  (display "Username: ") (flush-output)
  (define username (string-trim (string-downcase (read-line))))
  (display "Password: ") (flush-output)
  (define password (string-trim (read-line)))

  (define user-record
    (findf (lambda (u) (string=? (car u) username)) users))

  (if (not user-record)
      (begin (displayln "❌ User not found.") #f)
      (let ([stored-hash (cadr user-record)]
            [role (caddr user-record)]
            [input-hash (hash-password password)])
        (if (equal? stored-hash input-hash)
            (begin
              (displayln (format "✅ Authenticated as ~a (role: ~a)" username role))
              role)
            (begin
              (displayln "❌ Incorrect password.")
              #f)))))

;; 🔍 Parse key-value pairs from decrypted string
(define (parse-record record-str)
  (map (lambda (kv)
         (let ([parts (string-split (string-trim kv) ":")])
           (if (= (length parts) 2)
               (let ([key (string-downcase (string-trim (first parts)))]
                     [val (string-trim (second parts))])
                 (cons key val))
               (cons "unknown" kv))))
       (string-split (string-trim record-str) ",")))

;; 👁 Mask fields based on role
(define (mask-data-for-role data role)
  (define raw-allowed
    (cond
      [(assoc role user-access-rules) => cdr]
      [else '()]))
  (define allowed-keys (map symbol->string raw-allowed))
  (define parsed (parse-record data))
  (define filtered
    (filter (lambda (kv) (member (car kv) allowed-keys)) parsed))
  (string-join
   (map (lambda (kv) (format "~a: ~a" (car kv) (cdr kv))) filtered)
   ", "))

;; 🔄 Normalize values for consistency and compliance
(define (normalize-data record)
  (map (lambda (kv)
         (define k (car kv))
         (define v (cdr kv))
         (cond
           ;; Normalize name field
           [(string=? k "name")
            (let ([clean-name (string-titlecase v)])
              (displayln (format "✅ Normalized Name: ~a → ~a" v clean-name))
              (cons k clean-name))]

           ;; Normalize salary field with logging
           [(string=? k "salary")
            (with-handlers ([exn:fail?
                             (lambda (_)
                               (displayln (format "⚠️ Invalid salary value: ~a" v))
                               (cons k v))])
              (let* ([clean-salary (string-replace v "," "")]
                     [numeric-salary (string->number clean-salary)])
                (if numeric-salary
                    (let ([formatted-salary (number->string numeric-salary)])
                      (displayln (format "✅ Normalized Salary: ~a → ~a" v formatted-salary))
                      (cons k formatted-salary))
                    (begin
                      (displayln (format "⚠️ Salary not numeric: ~a" v))
                      (cons k v)))))]

           ;; Normalize SSN field
           [(string=? k "ssn")
            (let ([clean-ssn (string-replace v "-" "")])
              (displayln (format "✅ Normalized SSN: ~a → ~a" v clean-ssn))
              (cons k clean-ssn))]

           ;; Preserve unknown fields
           [else
            (cons k v)]))
       record))



;; 📝 Log each transformation with role, input/output, and action
(define (log-transformation user-role action input output)
  (define timestamp (current-inexact-milliseconds))
  (define entry (format "[~a] Role: ~a | Action: ~a | Input: ~a | Output: ~a" timestamp user-role action input output))
  (set! audit-log (cons entry audit-log)))

;; 🔍 Step 0: Convert Excel to CSV-style if needed
(define xlsx-file "input.xlsx")
(define csv-file "input.csv")
(define decrypted-file "input-decrypted.csv")

(when (file-exists? xlsx-file)
  (system (string-append "python crypto.py xlsx-to-lines " xlsx-file " " csv-file))

  (displayln "✅ Extracted lines from Excel."))

;; 🔐 Encrypt CSV
(system (string-append "python crypto.py encrypt " csv-file " encrypted-input.csv"))

;; 🔓 Decrypt CSV
(system (string-append "python crypto.py decrypt encrypted-input.csv " decrypted-file))

;; 👤 Authenticate user
(define user-role (login))

(when user-role
  (define csv-lines
    (call-with-input-file decrypted-file
      (lambda (in) (port->lines in))))

  (define headers (string-split (car csv-lines) ","))
  (define data-rows (cdr csv-lines))

  (call-with-output-file "output.csv"
    (lambda (out)
      (for-each
       (lambda (row)
         (define fields (string-split row ","))
         (displayln (format "📄 Raw Row Fields: ~a" fields))
         (define parsed-record
  (map (lambda (kv)
         (let ([parts (string-split (string-trim kv) ":")])
           (if (= (length parts) 2)
               (let ([key (string-downcase (string-trim (first parts)))])
                 (cons key (string-trim (second parts))))
               (cons "unknown" kv))))
       fields))
         (displayln (format "🔍 Parsed Key-Value Record: ~a" parsed-record))


         (define allowed-keys (map symbol->string (cdr (assoc user-role user-access-rules))))
         (define masked-record (filter (lambda (kv) (member (car kv) allowed-keys)) parsed-record))
         (displayln (format "👉 Masked Record: ~a" masked-record))

         (define normalized (normalize-data masked-record))
         (displayln (format "🧪 Normalized Record: ~a" normalized))

         (define line (write-csv-row normalized))
         (displayln (format "🧪 Final CSV Line: ~a" line))

         (displayln line out)
         (log-transformation user-role "row-normalize" row line))
       data-rows))
    #:exists 'replace)

  ;; 📝 Write audit log
  (call-with-output-file "audit.txt"
    (lambda (out)
      (for-each (lambda (line) (displayln line out)) (reverse audit-log)))
    #:exists 'replace)

  ;; 🔐 Encrypt and hash audit log
  (system "python crypto.py encrypt audit.txt audit-encrypted.txt")
  (system "python crypto.py hash audit.txt audit-hash.txt")

  ;; ✅ Verify audit integrity
  (displayln "\n🔐 Verifying Audit Integrity...")
  (system "python crypto.py verify audit-encrypted.txt audit-hash.txt")

  ;; 🧾 Display audit log for screenshot
  (displayln "\n📄 Raw Audit Log Preview:")
  (for-each displayln (reverse audit-log)))


  


