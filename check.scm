#!/usr/bin/env guile
!#
; vim:syntax=scheme expandtab
(load "agentx/tools.scm")
(load "agentx/encode.scm")
(load "agentx/decode.scm")
(load "agentx/session.scm")

(use-syntax (ice-9 syncase))
(define-syntax assert
  (syntax-rules ()
                ((assert x)
                 (if (not x) (throw 'Assertion-failed 'x)))))

;; Test assert

(assert #t)
(assert (catch 'Assertion-failed
               (lambda () (assert #f) #f)
               (lambda (key expr) #t)))

;; Test tools

(assert (equal? ((@@ (agentx tools) match-prefix) '(1 2 3) '(1 2 3 4 5)) '(4 5)))
(assert (eqv? ((@@ (agentx tools) match-prefix) '(1 2 3) '(3 2 1 1 1)) #f))
(assert (eqv? ((@@ (agentx tools) match-prefix) '(1 2 3) '(1 2)) #f))
(assert (equal? ((@@ (agentx tools) match-internet-prefix) '(1 3 6 1 2 3 4)) '(2 3 4)))
(assert (eqv? ((@@ (agentx tools) match-internet-prefix) '(1 4 6 1 2 3 4)) #f))

;; Test encoders

(assert (string=? "\0" (with-output-to-string (lambda () ((@@ (agentx encode) byte) 0)))))
(assert (string=? "A"  (with-output-to-string (lambda () ((@@ (agentx encode) byte) 65)))))
(assert (string=? "AB" (with-output-to-string (lambda () ((@@ (agentx encode) byte) 65) ((@@ (agentx encode) byte) 66)))))
(assert (string=? "AB"       (with-output-to-string (lambda () ((@@ (agentx encode) half-word) #x4142)))))
(assert (string=? "ABCD"     (with-output-to-string (lambda () ((@@ (agentx encode) word) #x41424344)))))
(assert (string=? "ABCDEFGH" (with-output-to-string (lambda () ((@@ (agentx encode) double-word) #x4142434445464748)))))

(assert (string=? "\0" (with-output-to-string (lambda () ((@@ (agentx encode) padd) 1)))))
(assert (string=? "\0\0\0" (with-output-to-string (lambda () ((@@ (agentx encode) padd) 3)))))
(assert (string=? "" (with-output-to-string (lambda () ((@@ (agentx encode) padd) 0)))))

(assert (string=? "\0\0\0\x04ABCD"  (with-output-to-string (lambda () ((@@ (agentx encode) octet-string) "ABCD")))))
(assert (string=? "\0\0\0\x03ABC\0" (with-output-to-string (lambda () ((@@ (agentx encode) octet-string) "ABC")))))
(assert (string=? "\0\0\0\x02AB\0\0" (with-output-to-string (lambda () ((@@ (agentx encode) octet-string) "AB")))))
(assert (string=? "\0\0\0\x01A\0\0\0" (with-output-to-string (lambda () ((@@ (agentx encode) octet-string) "A")))))
(assert (string=? "\0\0\0\0" (with-output-to-string (lambda () ((@@ (agentx encode) octet-string) "")))))

(assert (eqv? 6 ((@@ (agentx encode) flags->byte) '(new-index any-index))))

(assert (string=? "\x06\0\0\0" (with-output-to-string (lambda () ((@@ (agentx encode) timeout) 6)))))

;; Test decoders

(assert (eqv? 12 (with-input-from-string "\x0C" (lambda () ((@@ (agentx decode) byte))))))
(assert (eqv? #x1234 (with-input-from-string "\x12\x34" (lambda () ((@@ (agentx decode) half-word))))))
(assert (eqv? #x12345678 (with-input-from-string "\x12\x34\x56\x78" (lambda () ((@@ (agentx decode) word))))))
(assert (eqv? #x123456789abcdef0 (with-input-from-string "\x12\x34\x56\x78\x9a\xbc\xde\xf0" (lambda () ((@@ (agentx decode) double-word))))))
(assert (equal? '(1 2 3) (with-input-from-string "\0\0\0\x01\0\0\0\x02\0\0\0\x03" (lambda () ((@@ (agentx decode) word-list) 3)))))

(assert (string=? "abc" (with-input-from-string "abc" (lambda () ((@@ (agentx decode) rstring) 3)))))
(assert (string=? "abc" (with-input-from-string "\0\0\0\x03abc\0" (lambda () ((@@ (agentx decode) octet-string))))))
(assert (string=? "ab" (with-input-from-string "\0\0\0\x02ab\0\0" (lambda () ((@@ (agentx decode) octet-string))))))
(assert (string=? "a" (with-input-from-string "\0\0\0\x01a\0\0\0" (lambda () ((@@ (agentx decode) octet-string))))))
(assert (string=? "" (with-input-from-string "\0\0\0\0" (lambda () ((@@ (agentx decode) octet-string))))))

;; Test encoding-decoding

(define (connect-ios writer reader)
  (with-input-from-string
    (with-output-to-string writer)
    reader))

(define obj-id1 '(1 2 3 4 5))
(define obj-id2 '(1 3 6 1 1 2 3))
(let ((test (lambda (obj-id)
              (assert (equal? obj-id
                              (connect-ios
                                (lambda () ((@ (agentx encode) object-identifier) obj-id))
                                (lambda () ((@ (agentx decode) object-identifier)))))))))
  (test obj-id1)
  (test obj-id2))

(let ((test (lambda (str)
              (assert (string=? str
                                (connect-ios
                                  (lambda () ((@ (agentx encode) octet-string) str))
                                  (lambda () ((@ (agentx decode) octet-string)))))))))
  (test "")
  (test "a")
  (test "ab")
  (test "abc")
  (test "abcd")
  (test "the lazzy dog lay under the quick brown fox"))

(define varbind1 (list 'integer obj-id1 12))
(define varbind2 (list 'octet-string obj-id2 "foobar"))
(define varbind3 (list 'counter64 obj-id1 123123123123123))
(define varbind4 (list 'ip-address obj-id2 "\xC0\xA8\x01\x02"))

(let ((test (lambda (var)
              (assert (equal? var
                              (connect-ios
                                (lambda () (apply (@ (agentx encode) varbind) var))
                                (lambda () ((@ (agentx decode) varbind)))))))))
  (test varbind1)
  (test varbind2)
  (test varbind3)
  (test varbind4))

(let ((args (list 'register-pdu (list 'new-index 'non-default-context 'network-byte-order) 1 2 3 4)))
  (assert (equal? args
                  (connect-ios
                    (lambda () (apply (@ (agentx encode) pdu-header) args))
                    (lambda () (call-with-values (lambda () ((@ (agentx decode) pdu-header))) list))))))

;; Test Session

(load "agentx/session.scm")

(define getters #(('(1 2 3 1) (lambda () '(integer 666)))
                  ('(1 2 3 2) (lambda () '(octet-string "foo")))
                  ('(1 2 3 3) (lambda () '(counter64 123456789000)))))
(define sess1 ((@ (agentx session) make-session) "test" '(1 2 3) getters))
(assert (eq? ((@@ (agentx session) session-state) sess1) 'closed))
(with-output-to-string (lambda () ((@ (agentx session) open) sess1)))
(assert (eq? ((@@ (agentx session) session-state) sess1) 'opening))

; Send a fake response with a session id

(with-output-to-string
  (lambda ()
    (connect-ios
      (lambda () ((@ (agentx session) response) 12345 1 2 0 'no-agentx-error 0))
      (lambda () ((@ (agentx session) handle-pdu) sess1)))))
(assert (eq? ((@@ (agentx session) session-state) sess1) 'registering))
(assert (eq? ((@@ (agentx session) session-id) sess1) 12345))

; TODO: send a fake response to the register

(display "Ok\n")
(exit 0)
