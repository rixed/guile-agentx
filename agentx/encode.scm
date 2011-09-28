; vim:syntax=scheme expandtab
;;; This file implements the various required encoders for AgentX.
;;; All encoders write to default output port.

(define-module (agentx encode))
(export byte
        half-word
        word
        double-word
        object-identifier
        search-range
        octet-string
        varbind
        varbind-list
        pdu-header
        timeout
        reason
        error)
(use-modules (agentx tools)
             (ice-9 optargs)
             (ice-9 format)
             (rnrs io ports))

(define (byte b)
  (debug "> ~2,'0x" b)
  (put-u8 (current-output-port) b))

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

(define (half-word w)
  ((case (fluid-ref endianness)
    ((big)    half-word-big-endian)
    ((little) half-word-little-endian)) w))

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

(define (word w)
  ((case (fluid-ref endianness)
     ((big)    word-big-endian)
     ((little) word-little-endian)) w))

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

(define (double-word w)
  ((case (fluid-ref endianness)
     ((big)    double-word-big-endian)
     ((little) double-word-little-endian)) w))

(define (word-list lst)
  (if (not (null? lst))
    (let ((w (car lst)))
      (word w)
      (word-list (cdr lst)))))

(define* (object-identifier lst-id #:optional (include 0))
  (let* ((suffix  (match-internet-prefix lst-id))
         (prefix  (if (list? suffix) (car suffix) 0))
         (lst     (if (list? suffix) (cdr suffix) lst-id)))
    (debug ">object-identifier ~a" lst-id)
    (byte (length lst))
    (byte prefix)
    (byte include)
    (byte 0)
    (word-list lst)))

(define (search-range lst-id1 lst-id2)
  (debug ">search-range ~a - ~a" lst-id1 lst-id2)
  (object-identifier lst-id1)
  (object-identifier lst-id2))

(define (wstring str)
  (if (not (string-null? str))
    (begin
      (byte (char->integer (string-ref str 0)))
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
    (debug ">octet-string ~a" str)
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
               ((end-of-mib-view)  130)
               (else (throw 'error "Unknown varbind type")))))

(define (varbind-data type data)
  ((cond ((memq type '(integer counter32 gauge32 time-ticks)) word)
         ((eq? type 'counter64) double-word)
         ((eq? type 'object-identifier) object-identifier)
         ((memq type '(opaque octet-string)) octet-string)
         ((eq? type 'ip-address) (lambda (data)
                                   (with-fluids ((endianness 'big))
                                                (octet-string data))))
         (else ignore))
   data))

(define (varbind type name data)
  (debug ">varbind ~a ~a ~a" type name data)
  (varbind-type type)
  (half-word 0)
  (object-identifier name)
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
              ((response-pdu)          18)
              (else (throw 'error "Unknown PDU type")))))

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
  (byte (flags->byte
          (if (eq? (fluid-ref endianness) 'big)
            (cons 'network-byte-order flags)
            flags))))

(define (pdu-header type flags session-id transaction-id packet-id payload-len)
  (debug ">PDU type ~a, flags ~a" type flags)
  (byte 1)  ; version
  (pdu-header-type type)
  (pdu-header-flags flags)
  (byte 0)
  (word session-id)
  (word transaction-id)
  (word packet-id)
  (word payload-len))

(define (timeout t)
  (byte t)(byte 0)(half-word 0))

(define (reason r)
  (byte (case r
          ((other)          1)
          ((parse-error)    2)
          ((protocol-error) 3)
          ((timeouts)       4)
          ((shutdown)       5)
          ((by-manager)     6)
          (else (throw 'error "Unknown reason"))))
  (byte 0)(half-word 0))

(define (error r)
  (half-word (case r
               ((no-agentx-error)           0)
               ((gen-error)                 5)
               ((no-access)                 6)
               ((wrong-type)                7)
               ((wrong-length)              8)
               ((wrong-encoding)            9)
               ((wrong-value)              10)
               ((no-creation)              11)
               ((inconsistent-value)       12)
               ((resource-unavailable)     13)
               ((commit-failed)            14)
               ((undo-failed)              15)
               ((not-writable)             17)
               ((inconsistent-name)        18)
               ((open-failed)             256)
               ((not-open)                257)
               ((index-wrong-type)        258)
               ((index-already-allocated) 259)
               ((index-none-available)    260)
               ((index-not-allocated)     261)
               ((unsupported-context)     262)
               ((duplicate-registration)  263)
               ((unknown-registration)    264)
               ((unknown-agent-caps)      265)
               ((parse-error)             266)
               ((request-denied)          267)
               ((processing-error)        268)
               (else (throw 'error "Unknown error code")))))

