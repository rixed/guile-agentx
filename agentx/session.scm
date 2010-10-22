; vim:syntax=scheme expandtab
;;; This file implements agentX protocol.

(define-module (agentx session))
(use-modules ((agentx encode) :renamer (symbol-prefix-proc 'enc:))
			 ((agentx decode) :renamer (symbol-prefix-proc 'dec:))
             ((agentx tools)  :renamer (symbol-prefix-proc 'tool:))
			 (ice-9 receive))
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

(define snmp-trap-oid-0 (list 1 3 6 1 6 3 1 1 4 1 0))
(define sys-uptime-0 (list 1 3 6 1 2 1 1 3 0))

; getters is a vector of ((w x y z) procedure), in lexicographical order
(define session-rtd        (make-record-type "session" '(descr id state subtree getters)))
(define (make-session descr tree getters)
  ((record-constructor session-rtd '(descr state subtree getters)) descr 'closed tree getters))
(define session?           (record-predicate session-rtd))
(define session-descr      (record-accessor session-rtd 'descr))
(define session-id         (record-accessor session-rtd 'id))
(define session-state      (record-accessor session-rtd 'state))
(define session-subtree    (record-accessor session-rtd 'subtree))
(define session-getters    (record-accessor session-rtd 'getters))
(define set-session-id!    (record-modifier session-rtd 'id))
(define set-session-state! (record-modifier session-rtd 'state))

(define (vector-find pred vec)
  (letrec ((find-rec (lambda (n)
					   (if (< n (vector-length vec))
						 (if (pred (vector-ref vec n))
						   n
						   (find-rec (+ n 1)))
						 #f))))
	(find-rec 0)))

; returns the index in the vector of the getters
(define (session-find-getter session oid)
  (let* ((getters   (session-getters session))
		 (match-oid (lambda (getter)
					  (let ((oid_ (car getter))
							(get  (cdr getter)))
						(equal? oid oid_)))))
	(vector-find match-oid getters)))

; returns the getter function for this oid
(define (session-get session oid)
  (let ((n       (session-find-getter session oid))
        (getters (session-getters session)))
	(if n
	  (cdr (vector-ref getters n))
	  (throw 'no-such-oid oid))))

; returns next oid after this one, or '() if we reached end of subtree
(define (session-get-next session oid)
  (let ((getters (session-getters session)))
    (if (equal? (session-subtree session) oid)
      ; Return the oid of the first getter
      (car (vector-ref getters 0))
      ; Else look for this oid in our getters
      (let ((n (session-find-getter session oid)))
        (if n
          (if (< n (- (vector-length getters) 1))
            (car (vector-ref getters (+ n 1)))
            '())
          (throw 'no-such-oid oid))))))

(define next-packet-id
  (let ((id 0))
	(lambda ()
	  (set! id (+ id 1))
	  id)))

(define default-timeout 60)

(define (open-pdu descr)
  (let* ((payload (with-output-to-string
					(lambda ()
					  (enc:timeout default-timeout)
					  (enc:object-identifier '())
					  (enc:octet-string descr))))
		 (payload-len (string-length payload))
		 (packet-id   (next-packet-id)))
	(enc:pdu-header 'open-pdu '() 0 0 packet-id payload-len)
	(display payload)))

(define (close-pdu reason session-id)
  (let* ((payload (with-output-to-string
					(lambda ()
					  (enc:reason reason))))
		 (payload-len (string-length payload))
		 (packet-id   (next-packet-id)))
	(enc:pdu-header 'close-pdu '() session-id 0 packet-id payload-len)
	(display payload)))

(define (register-pdu ids session-id)
  (let* ((payload (with-output-to-string
					(lambda ()
                      (enc:byte default-timeout)
                      (enc:byte 127)
                      (enc:byte 0)  ; no range_subid
                      (enc:byte 0)
					  (enc:object-identifier ids))))
		 (payload-len (string-length payload))
		 (packet-id   (next-packet-id)))
	(enc:pdu-header 'register-pdu '() session-id 0 packet-id payload-len)
	(display payload)))

(define (notify-pdu vars session-id)
  (let* ((payload (with-output-to-string
                    (lambda ()
                      (enc:varbind-list vars))))
         (payload-len (string-length payload))
         (packet-id   (next-packet-id)))
    (enc:pdu-header 'notify-pdu '() session-id 0 packet-id payload-len)
    (display payload)))

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
  (let* ((getter (session-get session oid))
		 (result (getter))
		 (type   (car result))
		 (data   (cadr result)))
	(enc:varbind type oid data)))

; write a varbind encoding end-of-mib-view
(define (answer-end-of-mib session oid)
  (enc:varbind 'end-of-mib-view oid ""))

; write the varbind-list corresponding to oids start to stop
(define (get-search-range session start stop)
  (answer-oid session start)
  (if (not (null? stop))
	(let ((next (next-oid start)))
	  (if (not (eqv? next stop))
		(get-search-range session next stop)))))

; write the varbind-list corresponding to oids start (FIXME: stop is ignored for now)
(define (get-next-search-range session start stop)
  (let ((next-oid (session-get-next session start)))
    (if (null? next-oid)
	  (answer-end-of-mib session start)
	  (answer-oid session next-oid))))

; read some searchrange and write the corresponding varbind list
(define (foreach-search-ranges func session payload-len)
  (if (> payload-len 0)
	(let* ((start (dec:object-identifier))
		   (stop  (dec:object-identifier)))
	  (func session start stop))))

(define (handle-get session flags sess-id tx-id packet-id payload-len)
  (if (check-session session sess-id)
	(let* ((varbind-str (with-output-to-string
                          (lambda ()
                            (catch 'no-such-oid
                                   (lambda () (foreach-search-ranges get-search-range session payload-len))
                                   (lambda (key oid)
                                     (enc:varbind 'no-such-instance oid ""))))))
           (varbind-len (string-length varbind-str)))
      (response (session-id session) tx-id packet-id varbind-len 'no-agentx-error 0)
      (display varbind-str))))

(define (handle-get-next session flags sess-id tx-id packet-id payload-len)
  (if (check-session session sess-id)
	(let* ((varbind-str (with-output-to-string
						  (lambda () (foreach-search-ranges get-next-search-range session payload-len))))
		   (varbind-len (string-length varbind-str)))
	  (response (session-id session) tx-id packet-id varbind-len 'no-agentx-error 0)
	  (display varbind-str))))

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

(define (handle-pdu session . expected-type)
  (receive
	(type flags sess-id tx-id packet-id payload-len) (dec:pdu-header)
    (if (and (not (null? expected-type))
             (not (eq? (car expected-type) type)))
      (throw 'session-error "Unexpected answer of wrong type"))
    (with-fluids ((tool:endianness (tool:endianness-of-flags flags)))
                 ((case type
                    ((get-pdu)      handle-get)
                    ((get-next-pdu) handle-get-next)
                    ((get-bulk-pdu) handle-get-bulk)
                    ((response-pdu) handle-response)
                    (else           handle-unknown)) session flags sess-id tx-id packet-id payload-len))))

; TODO: a mutex in the session to protect the fd (notify must not occur while serving a master agent request)
