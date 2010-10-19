; vim:syntax=scheme expandtab
;;; This file implements the various required (en)coders for AgentX.
;;; All encoders write input structures to default output port, while
;;; all decoders read input stream from default input port.
;;; Byte ordering is always big endian for now (since it works with
;;; the ip-address type, but in the future we would something like :
;;; (with-little-endian-encoding (...))

(define-module (agentx tools))
(export ignore
        match-prefix
        match-internet-prefix)


;;;
;;; Tools
;;;


(define (ignore x) *unspecified*)

;; Returns either the rest of the string, or #f if no match occur
(define (match-prefix prefix lst)
  (cond ((null? prefix)                lst)
        ((null? lst)                   #f)
        ((eqv? (car lst) (car prefix)) (match-prefix (cdr prefix) (cdr lst)))
        (else #f)))

(define (match-internet-prefix lst) (match-prefix '(1 3 6 1) lst))


;;;
;;; Coders
;;;


(define-module (agentx encode))
(export object-identifier
        search-range
        octet-string
        varbind
        varbind-list
        pdu-header)
(use-modules (agentx tools)
             (ice-9 optargs))

(define (byte b) (write-char (integer->char b)))

(define (half-word-big-endian w)
  (let ((b0 (logand #xFF w))
        (b1 (logand #xFF (ash w -8))))
    (byte b1)
    (byte b0)))

(define (half-word-little-endian w)
  (let ((b0 (logand #xFF w))
        (b1 (logand #xFF (ash w -8))))
    (byte b0)
    (byte b1)))

(define half-word half-word-big-endian)

(define (word-big-endian w)
  (let ((b0 (logand #xFFFF w))
        (b1 (logand #xFFFF (ash w -16))))
    (half-word b1)
    (half-word b0)))

(define (word-little-endian w)
  (let ((b0 (logand #xFFFF w))
        (b1 (logand #xFFFF (ash w -16))))
    (half-word b0)
    (half-word b1)))

(define word word-big-endian)

(define (double-word-big-endian w)
  (let ((b0 (logand #xFFFFFFFF w))
        (b1 (logand #xFFFFFFFF (ash w -32))))
    (word b1)
    (word b0)))

(define (double-word-little-endian w)
  (let ((b0 (logand #xFFFFFFFF w))
        (b1 (logand #xFFFFFFFF (ash w -32))))
    (word b0)
    (word b1)))

(define double-word double-word-big-endian)

(define (word-list lst)
  (if (not (null? lst))
    (let ((w (car lst)))
      (word w)
      (word-list (cdr lst)))))

(define* (object-identifier lst-id #:optional (include 0))
  (let* ((suffix  (match-internet-prefix lst-id))
         (prefix  (if (list? suffix) (car suffix) 0))
         (lst     (if (list? suffix) (cdr suffix) lst-id)))
    (byte (length lst))
    (byte prefix)
    (byte include)
    (byte 0)
    (word-list lst)))

(define (search-range lst-id1 lst-id2)
  (object-identifier lst-id1)
  (object-identifier lst-id2))

(define (wstring str)
  (if (not (string-null? str))
    (begin
      (write-char (string-ref str 0))
      (wstring (substring/shared str 1)))))

(define (padd padding)
  (if (not (eqv? 0 padding))
    (begin
      (byte 0)
      (padd (- padding 1)))))

(define (octet-string str)
  (let* ((len     (string-length str))
         (rest    (logand #b11 len))
         (padding (if (eqv? rest 0) 0 (- 4 rest))))
    (word len)
    (wstring str)
    (padd padding)))

(define (varbind-type type)
  (half-word (case type
               ((integer)            2)
               ((octet-string)       4)
               ((null)               5)
               ((object-identifier)  6)
               ((ip-address)        64)
               ((counter32)         65)
               ((gauge32)           66)
               ((time-ticks)        67)
               ((opaque)            68)
               ((counter64)         70)
               ((no-such-object)   128)
               ((no-such-instance) 129)
               ((end-of-mib-view)  130))))

(define (varbind-data type data)
  ((cond ((memq type '(integer counter32 gauge32 time-ticks)) word)
         ((eq? type 'counter64) double-word)
         ((eq? type 'object-identifier) object-identifier)
         ((memq type '(ip-address opaque octet-string)) octet-string)
         (else ignore))
   data))

(define (varbind type lst-id data)
  (varbind-type type)
  (half-word 0)
  (object-identifier lst-id)
  (varbind-data type data))

(define (varbind-list lst)
  (if (not (null? lst))
    (let* ((type   (caar lst))
           (lst-id (cadar lst))
           (data   (caddar lst)))
      (varbind type lst-id data)
      (varbind-list (cdr lst)))))

(define (pdu-header-type type)
  (byte (case type
              ((open-pdu)               1)
              ((close-pdu)              2)
              ((register-pdu)           3)
              ((unregister-pdu)         4)
              ((get-pdu)                5)
              ((get-next-pdu)           6)
              ((get-bulk-pdu)           7)
              ((test-set-pdu)           8)
              ((commit-set-pdu)         9)
              ((undo-set-pdu)          10)
              ((cleanup-set-pdu)       11)
              ((notify-pdu)            12)
              ((ping-pdu)              13)
              ((index-allocate-pdu)    14)
              ((index-deallocate-pdu)  15)
              ((add-agent-caps-pdu)    16)
              ((remove-agent-caps-pdu) 17)
              ((response-pdu)          18))))

(define (flags->byte flags)
  (if (null? flags)
    0
    (logior (case (car flags)
                  ((instance-registration) 1)
                  ((new-index)             2)
                  ((any-index)             4)
                  ((non-default-context)   8)
                  ((network-byte-order)   16))
            (flags->byte (cdr flags)))))

(define (pdu-header-flags flags)
  (byte (flags->byte flags)))

(define (pdu-header type flags session-id transaction-id packet-id payload-len)
  (byte 1)  ; version
  (pdu-header-type type)
  (pdu-header-flags flags)
  (byte 0)
  (word session-id)
  (word transaction-id)
  (word packet-id)
  (word payload-len))


;;;
;;; Decoders
;;;


(define-module (agentx decode))
(export object-identifier
        search-range
        octet-string
        varbind
        varbind-list
        pdu-header)
(use-modules (agentx tools))

(define (byte) (char->integer (read-char)))

(define (half-word-big-endian)
  (let* ((b0 (byte))
         (b1 (byte)))
    (logior b1 (ash b0 8))))

(define (half-word-little-endian)
  (let* ((b0 (byte))
         (b1 (byte)))
    (logior b0 (ash b1 8))))

(define half-word half-word-big-endian)

(define (word-big-endian)
  (let* ((b0 (half-word))
         (b1 (half-word)))
    (logior b1 (ash b0 16))))

(define (word-little-endian)
  (let* ((b0 (half-word))
         (b1 (half-word)))
    (logior b0 (ash b1 16))))

(define word word-big-endian)

(define (double-word-big-endian)
  (let* ((b0 (word))
         (b1 (word)))
    (logior b1 (ash b0 32))))

(define (double-word-little-endian)
  (let* ((b0 (word))
         (b1 (word)))
    (logior b0 (ash b1 32))))

(define double-word double-word-big-endian)

(define (word-list n)
  (if (eqv? 0 n)
    (list)
    (cons (word) (word-list (- n 1)))))

(define (object-identifier)
  (let* ((n-subid  (byte))
         (prefix   (byte))
         (include  (byte))  ; FIXME: use this
         (reserved (byte))
         (sub-ids  (word-list n-subid)))
    (if (eqv? 0 prefix) sub-ids (cons 1 (cons 3 (cons 6 (cons 1 (cons prefix sub-ids))))))))

(define (search-range)
  (cons (object-identifier)
        (object-identifier)))

(define (rstring len)
  (let ((str        (make-string len)))
    (letrec ((rchar (lambda (n)
                     (if (< n len)
                       (begin
                         (string-set! str n (read-char))
                         (rchar (+ n 1)))))))
      (rchar 0)
      str)))

(define (octet-string)
  (let* ((len     (word))
         (str     (rstring len))
         (rest    (logand #b11 (string-length str)))
         (padding (if (eqv? rest 0) 0 (- 4 rest))))
    (letrec ((skip (lambda (n) (if (> n 0) (begin (byte) (skip (- n 1)))))))
      (skip padding)
      str)))

(define (varbind-type)
  (case (half-word)
    ((2)   'integer)
    ((4)   'octet-string)
    ((5)   'null)
    ((6)   'object-identifier)
    ((64)  'ip-address)
    ((65)  'counter32)
    ((66)  'gauge32)
    ((67)  'time-ticks)
    ((68)  'opaque)
    ((70)  'counter64)
    ((128) 'no-such-object)
    ((129) 'no-such-instance)
    ((130) 'end-of-mib-view)))

(define (varbind-data type)
  ((cond ((memq type '(integer counter32 gauge32 time-ticks)) word)
         ((eq? type 'counter64) double-word)
         ((eq? type 'object-identifier) object-identifier)
         ((memq type '(ip-address opaque octet-string)) octet-string)
         (else ignore))))

(define (varbind)
  (let* ((type     (varbind-type))
         (reserved (half-word))
         (obj-id   (object-identifier))
         (data     (varbind-data type)))
    (list type obj-id data)))

(define (varbind-list n)
  (if (> n 0)
    (begin
      (cons (varbind) (varbind-list (- n 1))))))

(define (pdu-header-type)
  (case (byte)
    ((1)  'open-pdu)
    ((2)  'close-pdu)
    ((3)  'register-pdu)
    ((4)  'unregister-pdu)
    ((5)  'get-pdu)
    ((6)  'get-next-pdu)
    ((7)  'get-bulk-pdu)
    ((8)  'test-set-pdu)
    ((9)  'commit-set-pdu)
    ((10) 'undo-set-pdu)
    ((11) 'cleanup-set-pdu)
    ((12) 'notify-pdu)
    ((13) 'ping-pdu)
    ((14) 'index-allocate-pdu)
    ((15) 'index-deallocate-pdu)
    ((16) 'add-agent-caps-pdu)
    ((17) 'remove-agent-caps-pdu)
    ((18) 'response-pdu)))

(define (byte->flags x)
  (let ((flags (list)))
    (if (not (eqv? (logand x 16) 0)) (set! flags (cons 'network-byte-order flags)))
    (if (not (eqv? (logand x  8) 0)) (set! flags (cons 'non-default-context flags)))
    (if (not (eqv? (logand x  4) 0)) (set! flags (cons 'any-index flags)))
    (if (not (eqv? (logand x  2) 0)) (set! flags (cons 'new-index flags)))
    (if (not (eqv? (logand x  1) 0)) (set! flags (cons 'instance-registration flags)))
    flags))

(define (pdu-header-flags)
  (byte->flags (byte)))

(define (pdu-header)
  (let* ((version        (byte))
         (type           (pdu-header-type))
         (flags          (pdu-header-flags))
         (reserved       (byte))
         (session-id     (word))
         (transaction-id (word))
         (packet-id      (word))
         (payload-len    (word)))
    (list type flags session-id transaction-id packet-id payload-len)))

