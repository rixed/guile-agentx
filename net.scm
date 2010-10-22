; vim:syntax=scheme expandtab
;;; This file implements agentX subagent, connecting to local master.

(define-module (agentx net))
(use-modules ((agentx session)  :renamer (symbol-prefix-proc 'sess:)))
(export connect-master
        subagent)

; returns the port where to read from/write to
(define (connect-master)
  (let* ((sock (socket PF_UNIX SOCK_STREAM 0)))
    (connect sock AF_UNIX "/var/agentx/master")
    sock))

; loop forever with a freshly made session
(define (handle-loop session port)
  (set-current-input-port port)
  (set-current-output-port port)
  (sess:open session)
  (let loop ()
    (sess:handle-pdu session)
    (loop)))

(define (subagent descr tree getters)
  (let ((session (sess:make-session descr tree getters))
        (port    (connect-master)))
    (handle-loop session port)))

