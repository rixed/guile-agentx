; vim:syntax=scheme expandtab
;;; This file implements a simple net-snmp subagent

(use-modules ((agentx net) :renamer (symbol-prefix-proc 'net:)))

(define subtree '(1 3 6 1 4 1 18072))
(define getters (vector (cons (append subtree '(1 0)) (lambda () '(integer 666)))
                        (cons (append subtree '(2 0)) (lambda () '(octet-string "hello world")))
                        (cons (append subtree '(3 0)) (lambda () '(counter64 12345678900)))))

(net:subagent "simple" subtree getters)

