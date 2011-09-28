; vim:syntax=scheme expandtab
;;; This file implements the various required decoders for AgentX.
;;; All decoders read from default input port.

(define-module (agentx decode))
(export byte
        half-word
        word
        double-word
        object-identifier-with-include
        object-identifier
        search-range
        octet-string
        varbind
        varbind-list
        pdu-header
        timeout
        reason
        error
        skip)
(use-modules (agentx tools)
             (ice-9 format)
             (rnrs io ports))

(define (byte)
  (let ((char (get-u8 (current-input-port))))
    (debug "< ~2,'0x" char)
    char))

(define (half-word-big-endian)
  (let* ((b0 (byte))
         (b1 (byte)))
    (logior b1 (ash b0 8))))

(define (half-word-little-endian)
  (let* ((b0 (byte))
         (b1 (byte)))
    (logior b0 (ash b1 8))))

(define (half-word)
  (case (fluid-ref endianness)
    ((big)    (half-word-big-endian))
    ((little) (half-word-little-endian))))

(define (word-big-endian)
  (let* ((b0 (half-word))
         (b1 (half-word)))
    (logior b1 (ash b0 16))))

(define (word-little-endian)
  (let* ((b0 (half-word))
         (b1 (half-word)))
    (logior b0 (ash b1 16))))

(define (word)
  (case (fluid-ref endianness)
    ((big)    (word-big-endian))
    ((little) (word-little-endian))))

(define (double-word-big-endian)
  (let* ((b0 (word))
         (b1 (word)))
    (logior b1 (ash b0 32))))

(define (double-word-little-endian)
  (let* ((b0 (word))
         (b1 (word)))
    (logior b0 (ash b1 32))))

(define (double-word)
  (case (fluid-ref endianness)
    ((big)    (double-word-big-endian))
    ((little) (double-word-little-endian))))

(define (word-list n)
  (if (eqv? 0 n)
    (list)
    (cons (word) (word-list (- n 1)))))

(define (object-identifier-with-include)
  (let* ((n-subid  (byte))
         (prefix   (byte))
         (include  (eqv? (byte) 1))
         (reserved (byte))
         (sub-ids  (word-list n-subid))
         (ids      (if (eqv? 0 prefix)
                     sub-ids
                     (cons 1 (cons 3 (cons 6 (cons 1 (cons prefix sub-ids))))))))
    (debug "<object-identifier ~a (included: ~a)" ids include)
    (cons ids include)))

(define (object-identifier)
  (car (object-identifier-with-include)))

(define (search-range)
  (let* ((start-id-i (object-identifier-with-include))
         (stop-id    (object-identifier)))
    (debug "<search-range from ~a to ~a" start-id-i stop-id)
    (cons start-id-i stop-id)))

(define (rstring len)
  (let ((str        (make-string len)))
    (letrec ((rchar (lambda (n)
                     (if (< n len)
                       (begin
                         (string-set! str n (integer->char (byte)))
                         (rchar (+ n 1)))))))
      (rchar 0)
      str)))

(define (skip len)
  (debug "Skip ~a bytes" len)
  (if (> len 0) (begin (byte) (skip (- len 1)))))

(define (octet-string)
  (let* ((len     (word))
         (str     (rstring len))
         (rest    (logand #b11 (string-length str)))
         (padding (if (eqv? rest 0) 0 (- 4 rest))))
    (skip padding)
    str))

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
    ((130) 'end-of-mib-view)
    (else (throw 'error "Cannot parse varbind type"))))

(define (varbind-data type)
  ((cond ((memq type '(integer counter32 gauge32 time-ticks)) word)
         ((eq? type 'counter64) double-word)
         ((eq? type 'object-identifier) object-identifier)
         ((memq type '(opaque octet-string)) octet-string)
         ((eq? type 'ip-address) (lambda () (with-fluids ((endianness 'big))
                                                         (octet-string))))
         (else ignore))))

(define (varbind)
  (let* ((type     (varbind-type))
         (reserved (half-word))
         (obj-id   (object-identifier))
         (data     (varbind-data type)))
    (debug "<varbind type ~a, obj-id ~a, data ~a" type obj-id data)
    (list type obj-id data)))

(define (varbind-list)
  (if (eof-object? (lookahead-u8 (current-input-port)))
    (begin
      (debug "No more varbind to read")
      '())
    (begin
      (debug "Read another varbind...")
      (cons (varbind) (varbind-list)))))

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
    ((18) 'response-pdu)
    (else (throw 'error "Cannot parse PDU type"))))

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
         (flags          (pdu-header-flags)))
    (if (not (eq? version 1)) (throw 'error (simple-format #f "Bad version: ~a" version)))
    (with-fluids
      ((endianness (endianness-of-flags flags)))
      (let* ((reserved       (byte))
             (session-id     (word))
             (transaction-id (word))
             (packet-id      (word))
             (payload-len    (word)))
        (debug "<PDU type ~a, flags ~a" type flags)
        (values type flags session-id transaction-id packet-id payload-len)))))

(define (timeout)
  (let ((o (byte)))
    (byte)(half-word)
    byte))

(define (reason)
  (let ((r (byte)))
    (byte)(half-word)
    (case r
      ((1) 'other)
      ((2) 'parse-error)
      ((3) 'protocol-error)
      ((4) 'timeouts)
      ((5) 'shutdown)
      ((6) 'by-manager)
      (else (throw 'error "Cannot parse reason")))))

(define (error)
  (case (half-word)
    ((0)   'no-agentx-error)
    ((256) 'open-failed)
    ((257) 'not-open)
    ((258) 'index-wrong-type)
    ((259) 'index-already-allocated)
    ((260) 'index-none-available)
    ((261) 'index-not-allocated)
    ((262) 'unsupported-context)
    ((263) 'duplicate-registration)
    ((264) 'unknown-registration)
    ((265) 'unknown-agent-caps)
    ((266) 'parse-error)
    ((267) 'request-denied)
    ((268) 'processing-error)
    (else (throw 'error "Cannot parse error code"))))

