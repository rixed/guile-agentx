; vim:syntax=scheme filetype=scheme expandtab
;;; This file implements agentX protocol.

(define-module (agentx session))
(use-modules ((agentx encode) :renamer (symbol-prefix-proc 'enc:))
             ((agentx decode) :renamer (symbol-prefix-proc 'dec:))
             (agentx tools)
             (ice-9 receive)
             (rnrs io ports)
             (rnrs bytevectors))
(export snmp-trap-oid-0
        sys-uptime-0
        make-session
        session?
        session-descr
        session-id
        session-state
        session-subtree
        open
        register
        close
        notify
        response
        handle-pdu)

(define snmp-trap-oid-0 '(1 3 6 1 6 3 1 1 4 1 0))
(define sys-uptime-0    '(1 3 6 1 2 1 1 3 0))

; getters is a procedure returning an list of (oid . procedure), in lexicographical order
; likewise, setters is a procedure returning a list of (oid . procedure)
(define session-rtd        (make-record-type "session" '(descr id state subtree getters setters)))
(define (make-session descr tree getters setters)
  ((record-constructor session-rtd '(descr state subtree getters setters)) descr 'closed tree getters setters))
(define session?           (record-predicate session-rtd))
(define session-descr      (record-accessor session-rtd 'descr))
(define session-id         (record-accessor session-rtd 'id))
(define session-state      (record-accessor session-rtd 'state))
(define session-subtree    (record-accessor session-rtd 'subtree))
(define session-getters    (record-accessor session-rtd 'getters))
(define session-setters    (record-accessor session-rtd 'setters))
(define set-session-id!    (record-modifier session-rtd 'id))
(define set-session-state! (record-modifier session-rtd 'state))

; returns the value for this oid
(define (session-get session oid)
  (debug "session-get ~a" oid)
  (let* ((getters ((session-getters session)))
         (getter  (assoc-ref getters oid)))
    (if getter
        (getter)
        (throw 'no-such-oid oid))))

; sets the oid to this value
(define (session-set session oid value)
  (debug "session-set ~a <- ~a" oid value)
  (let* ((setters ((session-setters session)))
         (setter  (assoc-ref setters oid)))
    (if setter
        (setter value)
        (throw 'no-such-oid oid))))

; if included is false, returns next (oid . getter) (lexicographicaly) after this one
; if included is true, returns this (oid. getter) if we have a getter for it, or the next one.
; if not found, throw no-such-oid
(define (session-get-next session oid included)
  (debug "session-get-next ~a (included: ~a)" oid included)
  (letrec ((getters ((session-getters session)))
           (min-cmp (if included 0 1))
           (find-getter (lambda (getters)
                          (if (null? getters) (throw 'no-such-oid oid))
                          (let ((this-oid    (caar getters))
                                (this-getter (cdar getters)))
                            (debug "  comparing oid ~a and ~a" oid this-oid)
                            (if (>= (oid-compare this-oid oid) min-cmp)
                              (car getters)
                              (find-getter (cdr getters)))))))
    (find-getter getters)))

(define next-packet-id  ; FIXME: make me thread safe
  (let ((id 0))
    (lambda ()
      (set! id (+ id 1))
      id)))

(define default-timeout 60)

(define (open-pdu descr)
  (let* ((payload     (with-output-to-bytevector
                        (lambda ()
                          (enc:timeout default-timeout)
                          (enc:object-identifier '())
                          (enc:octet-string (string->utf8 descr)))))
         (payload-len (bytevector-length payload))
         (packet-id   (next-packet-id)))
    (enc:pdu-header 'open-pdu '() 0 0 packet-id payload-len)
    (put-bytevector (current-output-port) payload)))

(define (close-pdu reason session-id)
  (let* ((payload     (with-output-to-bytevector
                        (lambda ()
                          (enc:reason reason))))
         (payload-len (bytevector-length payload))
         (packet-id   (next-packet-id)))
    (enc:pdu-header 'close-pdu '() session-id 0 packet-id payload-len)
    (put-bytevector (current-output-port) payload)))

(define (register-pdu ids session-id)
  (let* ((payload     (with-output-to-bytevector
                        (lambda ()
                          (enc:byte default-timeout)
                          (enc:byte 127)
                          (enc:byte 0)  ; no range_subid
                          (enc:byte 0)
                          (enc:object-identifier ids))))
         (payload-len (bytevector-length payload))
         (packet-id   (next-packet-id)))
    (enc:pdu-header 'register-pdu '() session-id 0 packet-id payload-len)
    (put-bytevector (current-output-port) payload)))

(define (notify-pdu vars session-id)
  (let* ((payload     (with-output-to-bytevector
                        (lambda ()
                          (enc:varbind-list vars))))
         (payload-len (bytevector-length payload))
         (packet-id   (next-packet-id)))
    (enc:pdu-header 'notify-pdu '() session-id 0 packet-id payload-len)
    (put-bytevector (current-output-port) payload)))

(define (open session)
  (if (not (eq? (session-state session) 'closed))
    (throw 'error "session already opened"))
  (open-pdu (session-descr session))
  (set-session-state! session 'opening))

(define (close session reason)
  (close-pdu reason (session-id session))
  (set-session-state! session 'closed))

(define (register session)
  (let ((subtree (session-subtree session)))
    ; if subtree is null, don't register anything (usefull for sending just a notify)
    (if (not (null? subtree))
      (begin (register-pdu (session-subtree session) (session-id session))
             (set-session-state! session 'registering))
      (set-session-state! session 'opened))))

(define (notify session vars)   ; vars is a list of (type oid data)
  (notify-pdu vars (session-id session)))

(define (response session-id tx-id packet-id varbind-len error-code error-index)
  (enc:pdu-header 'response-pdu '() session-id tx-id packet-id (+ 8 varbind-len))
  (enc:word 0)  ; sysUpTime is ignored by master agent
  (enc:error error-code)
  (enc:half-word error-index))

(define (check-session session sess-id)
  (if (not (eqv? (session-id session) sess-id))
    (begin (response-error 'parse-error)
           #f)
    (if (not (eq? (session-state session) 'opened))
      (begin (response-error 'not-open)
             #f)
      #t)))

; write the varbind for the given oid
(define (answer-oid session oid)
  (debug "answer-oid ~a" oid)
  (let* ((result (session-get session oid))
         (type   (car result))
         (data   (cdr result)))
    (enc:varbind type oid data)))

; write a varbind encoding end-of-mib-view
(define (answer-end-of-mib session oid)
  (enc:varbind 'end-of-mib-view oid ""))

; write the varbind-list corresponding to oids start to stop (stop is supposed to be null for get-next PDU)
(define (get-search-range session start included stop)
  (answer-oid session start)
  (if (not (null? stop))
    (let ((next (next-oid start)))
      (if (not (eqv? next stop))
        (get-search-range session next #t stop)))))

; write the varbind-list corresponding to oids start (FIXME: stop is ignored for now : session-get-next should check that the oid it find is < stop)
(define (get-next-search-range session start included stop)
  (catch 'no-such-oid
         (lambda ()
           (answer-oid session (car (session-get-next session start included))))
         (lambda (key oid)
           (answer-end-of-mib session start))))

; read some searchrange and write the corresponding varbind list
; current input port must have all the chars ready (and not more)
(define (foreach-search-ranges func session)
  (if (not (eof-object? (lookahead-u8 (current-input-port))))
    (let* ((range    (dec:search-range))
           (start    (caar range))
           (included (cdar range))
           (stop     (cdr range)))
      (func session start included stop)
      (foreach-search-ranges func session))))

(define (read-bytes len)
  (get-bytevector-n (current-input-port) len))

(define (handle-get session flags sess-id tx-id packet-id payload-len)
  (if (check-session session sess-id)
    (let* ((payload     (read-bytes payload-len))
           (varbind-str (with-output-to-bytevector
                          (lambda ()
                            (with-input-from-bytevector payload
                              (lambda ()
                                (catch 'no-such-oid
                                       (lambda () (foreach-search-ranges get-search-range session))
                                       (lambda (key oid)
                                         (enc:varbind 'no-such-instance oid ""))))))))
           (varbind-len (bytevector-length varbind-str)))
      (response (session-id session) tx-id packet-id varbind-len 'no-agentx-error 0)
      (put-bytevector (current-output-port) varbind-str))))

(define (handle-get-next session flags sess-id tx-id packet-id payload-len)
  (if (check-session session sess-id)
    (let* ((payload     (read-bytes payload-len))
           (varbind-str (with-output-to-bytevector
                          (lambda ()
                            (with-input-from-bytevector payload
                              (lambda () (foreach-search-ranges get-next-search-range session))))))
           (varbind-len (bytevector-length varbind-str)))
      (response (session-id session) tx-id packet-id varbind-len 'no-agentx-error 0)
      (put-bytevector (current-output-port) varbind-str))))

(define (handle-response session flags sess-id tx-id packet-id payload-len)
  (let* ((sys-uptime        (dec:word))
         (error             (dec:error))
         (index             (dec:half-word))
         (dummy-varbind-lst (dec:skip (- payload-len 8))))
    (if (eq? error 'no-agentx-error)
      (case (session-state session)
        ((opening)     (set-session-id! session sess-id)
                       (register session))
        ((registering) (set-session-state! session 'opened))
        ((closed)      (throw 'session-error "Session is closed"))
        ((opened)      #t))   ; that's fine
      (throw 'session-error error index))))

(define (handle-test-set session flags sess-id tx-id packet-id payload-len)
  (if (check-session session sess-id)
    (let* ((payload    (read-bytes payload-len))
           (vb-list    (with-input-from-bytevector payload
                         (lambda ()
                           (debug "Reading varbind list for ~a bytes" payload-len)
                           (dec:varbind-list))))
           (first-err  'no-agentx-error)
           (last-tried 0))
      (for-each (lambda (vb)
                  (let ((type  (car vb))
                        (oid   (cadr vb))
                        (value (caddr vb)))
                    (if (eq? first-err 'no-agentx-error)
                        (catch 'no-such-oid
                               (lambda ()
                                 (session-set session oid value)
                                 (set! last-tried (1+ last-tried)))
                               (lambda (key oid)
                                 (set! first-err 'not-writable))))))
                vb-list)
      (response (session-id session) tx-id packet-id 0
                first-err
                (if (eq? first-err 'no-agentx-error) 0 last-tried)))))

; We merely ignore commit and cleanup request since we did eveything in handle-test-set
(define (handle-commit-set session flags sess-id tx-id packet-id payload-len)
  (if (check-session session sess-id)
      (response (session-id session) tx-id packet-id 0 'no-agentx-error 0)))

(define (handle-cleanup-set session flags sess-id tx-id packet-id payload-len)
  (if (check-session session sess-id)
      (response (session-id session) tx-id packet-id 0 'no-agentx-error 0)))

; So it's always impossible to rollback
(define (handle-undo-set session flags sess-id tx-id packet-id payload-len)
  (if (check-session session sess-id)
      (response (session-id session) tx-id packet-id 0 'undo-failed 1)))

(define (handle-pdu session . expected-type)
  (receive
    (type flags sess-id tx-id packet-id payload-len) (dec:pdu-header)
    (if (and (not (null? expected-type))
             (not (eq? (car expected-type) type)))
      (throw 'session-error "Unexpected answer of wrong type"))
    (with-fluids ((current-endianness (endianness-of-flags flags)))
                 ((case type
                    ((get-pdu)         handle-get)
                    ((get-next-pdu)    handle-get-next)
                    ((get-bulk-pdu)    handle-get-bulk)
                    ((response-pdu)    handle-response)
                    ((test-set-pdu)    handle-test-set)
                    ((commit-set-pdu)  handle-commit-set)
                    ((cleanup-set-pdu) handle-cleanup-set)
                    ((undo-set-pdu)    handle-undo-set)
                    (else              handle-unknown)) session flags sess-id tx-id packet-id payload-len))))

; TODO: a mutex in the session to protect the fd (notify must not occur while serving a master agent request)
