#!/bin/sh
GUILE_LOAD_PATH=./ guile -l example.scm
!#
; vim:syntax=scheme expandtab
;;; This file implements a simple net-snmp subagent

(use-modules ((agentx net)     :renamer (symbol-prefix-proc 'net:))
             ((agentx session) :renamer (symbol-prefix-proc 'sess:)))

(define subtree '(1 3 6 1 4 1 18072))
(define (getters)
  (list (cons (append subtree '(1 0)) (lambda () '(integer . 666)))
        (cons (append subtree '(2 0)) (lambda () '(octet-string . "hello world")))
        (cons (append subtree '(3 0)) (lambda () '(counter64 . 12345678900)))))

(define subagent (net:make-subagent "simple" subtree getters))

(call-with-new-thread (lambda () (net:loop subagent)))

(let loop ()
  (sleep 5)
  (display "Notify!\n")
  (net:notify subagent
    (list (list 'time-ticks sess:sys-uptime-0 12345)
          (list 'object-identifier sess:snmp-trap-oid-0 '(1 3 6 1 4 1 18072 1 0))
          (list 'octet-string (append subtree '(2 0)) "HELLO!")))
  (loop))

