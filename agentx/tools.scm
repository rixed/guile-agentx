; vim:syntax=scheme expandtab
;;; This file implements some small tools used here and there

(define-module (agentx tools))
(export ignore
        match-prefix
        match-internet-prefix
        current-endianness
        endianness-of-flags
        oid-compare
        debug?
        debug)
(use-modules (ice-9 format))
(define debug? #f)
(use-syntax (ice-9 syncase))

(define format-mutex (make-mutex))
(define (format-safe . args)
  (lock-mutex format-mutex)
  (let* ((c       (car args))
         (c_nl    (string-append (object->string (current-thread)) c "\n"))
         (args_nl (cons c_nl (cdr args))))
    (apply format (fdes->outport 2) args_nl))
  (unlock-mutex format-mutex))

(define-syntax debug
  (syntax-rules ()
                ((debug fmt ...)
                 (if debug? (begin
                              ((@@ (agentx tools) format-safe) fmt ...))))))

(define (ignore x) *unspecified*)

;; Returns either the rest of the string, or #f if no match occur
(define (match-prefix prefix lst)
  (cond ((null? prefix)                lst)
        ((null? lst)                   #f)
        ((eqv? (car lst) (car prefix)) (match-prefix (cdr prefix) (cdr lst)))
        (else #f)))

(define (match-internet-prefix lst) (match-prefix '(1 3 6 1) lst))

(define current-endianness (make-fluid))
(fluid-set! current-endianness 'big)

(define (endianness-of-flags flags)
  (if (memq 'network-byte-order flags)
    'big
    'little))

(define (oid-compare oid1 oid2)
  (if (null? oid1)
    (if (null? oid2) 0 -1)
    (if (null? oid2) 1
      (let ((h1 (car oid1))
            (h2 (car oid2)))
        (if (eqv? h1 h2)
          (oid-compare (cdr oid1) (cdr oid2))
          (if (< h1 h2) -1 1))))))

