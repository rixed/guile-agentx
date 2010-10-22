; vim:syntax=scheme expandtab
;;; This file implements agentX subagent, connecting to local master.

(define-module (agentx net))
(use-modules ((agentx session)  :renamer (symbol-prefix-proc 'sess:)))
(export make-subagent
        subagent?
        subagent-session
        subagent-port
        loop
        notify)

; returns the port where to read from/write to
(define (connect-master)
  (let* ((sock (socket PF_UNIX SOCK_STREAM 0)))
    (connect sock AF_UNIX "/var/agentx/master")
    sock))

(define subagent-rtd       (make-record-type "subagent" '(session port)))
(define subagent?          (record-predicate subagent-rtd))
(define subagent-session   (record-accessor subagent-rtd 'session))
(define subagent-port      (record-accessor subagent-rtd 'port))
(define (make-subagent descr tree getters)
  (let ((session (sess:make-session descr tree getters))
        (port    (connect-master)))
    ((record-constructor subagent-rtd '(session port)) session port)))

(define (loop subagent)
  (let ((port    (subagent-port subagent))
        (session (subagent-session subagent)))
    (set-current-input-port port)
    (set-current-output-port port)
    (sess:open session)
    (let process ()
      (sess:handle-pdu session)
      (process))))

; In order to keep the design simple, we open a new session, without registering any subtree
(define (notify subagent vars)
  (let* ((descr        (sess:session-descr (subagent-session subagent)))
         (new-subagent (make-subagent descr '() #()))
         (port         (subagent-port new-subagent))
         (session      (subagent-session new-subagent)))
    (set-current-input-port port)
    (set-current-output-port port)
    (sess:open session)
    (sess:handle-pdu session 'response-pdu) ; wait answer to open-pdu
    (sess:notify session vars)
    (sess:handle-pdu session 'response-pdu)))
