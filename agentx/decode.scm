; vim:syntax=scheme filetype=scheme expandtab
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
             (rnrs io ports)
             (rnrs bytevectors))

(define (get-bytevector len)
  (let ((bv (get-bytevector-n (current-input-port) len)))
    (debug "< ~a" bv)
    bv))

(define (byte)
  (bytevector-u8-ref (get-bytevector 1) 0))

(define (half-word-ref bv index)
  (case (fluid-ref current-endianness)
    ((big)    (bytevector-u16-ref bv index (endianness big)))
    ((little) (bytevector-u16-ref bv index (endianness little)))))

(define (half-word)
  (let ((bv (get-bytevector 2)))
    (half-word-ref bv 0)))

(define (word-ref bv index)
  (case (fluid-ref current-endianness)
    ((big)    (bytevector-u32-ref bv index (endianness big)))
    ((little) (bytevector-u32-ref bv index (endianness little)))))

(define (word)
  (let ((bv (get-bytevector 4)))
    (word-ref bv 0)))

(define (double-word-ref bv index)
  (case (fluid-ref current-endianness)
    ((big)    (bytevector-u64-ref bv index (endianness big)))
    ((little) (bytevector-u64-ref bv index (endianness little)))))

(define (double-word)
  (let ((bv (get-bytevector 8)))
    (double-word-ref bv 0)))

(define (word-list n)
  (let ((bv (get-bytevector (* n 4))))
    (case (fluid-ref current-endianness)
      ((big)    (bytevector->uint-list bv (endianness big) 4))
      ((little) (bytevector->uint-list bv (endianness little) 4)))))

(define (object-identifier-with-include)
  (let* ((bv       (get-bytevector 4))
         (n-subid  (bytevector-u8-ref bv 0))
         (prefix   (bytevector-u8-ref bv 1))
         (include  (eqv? 1 (bytevector-u8-ref bv 2)))
         (reserved (bytevector-u8-ref bv 3))
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

(define (skip len)
  (debug "Skip ~a bytes" len)
  (ignore (get-bytevector len)))

(define (octet-string)
  (let* ((len     (word))
         (str     (get-bytevector len))
         (rest    (logand #b11 len))
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
         ((eq? type 'ip-address) (lambda () (with-fluids ((current-endianness 'big))
                                                         (word))))
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
      (list))
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
    (with-fluids ((current-endianness (endianness-of-flags flags)))
      (let* ((bv             (get-bytevector 17))
             (reserved       (bytevector-u8-ref bv 0))
             (session-id     (word-ref bv 1))
             (transaction-id (word-ref bv 5))
             (packet-id      (word-ref bv 9))
             (payload-len    (word-ref bv 13)))
        (debug "<PDU type ~a, flags ~a" type flags)
        (values type flags session-id transaction-id packet-id payload-len)))))

(define (timeout)
  (let ((bv (get-bytevector 4)))
    (bytevector-u8-ref bv 0)))

(define (reason)
  (let ((bv (get-bytevector 4))
        (r  (bytevector-u8-ref bv 0)))
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

