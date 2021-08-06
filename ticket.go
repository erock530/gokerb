package kerb

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/erock530/asn1"
	"github.com/erock530/go.logging"
)

const (
	ticketDialTCPEnv = "TICKET_DIAL_TCP"
)

var (
	ticketDialTCP = strings.ToUpper(os.Getenv(ticketDialTCPEnv)) == "TRUE"
)

type request struct {
	cfg     *CredConfig
	client  principalName
	crealm  string
	ckey    key // only needed for AS requests when tgt == nil
	ckvno   int
	service principalName
	srealm  string
	till    time.Time
	flags   int
	tgt     *Ticket
	salt    []byte

	// Setup by request.do()
	nonce  uint32
	time   time.Time
	seqnum uint32
	sock   io.ReadWriteCloser
	proto  string
}

var notill = asn1.RawValue{
	Bytes: []byte("19700101000000Z"),
	Class: 0,
	Tag:   24,
}

// sendRequest sends a single ticket request down the sock writer. If r.tgt is
// set this is a ticket granting service request, otherwise its an
// authentication service request. Note this does not use any random data, so
// resending will generate the exact same byte stream. This is needed with UDP
// connections such that if the remote receives multiple retries it discards
// the latters as replays.
func (r *request) sendRequest() (err error) {
	defer recoverMust(&err)

	body := kdcRequestBody{
		Client:       r.client,
		ServiceRealm: r.srealm,
		Service:      r.service,
		Flags:        flagsToBitString(r.flags),
		Till:         notill,
		Nonce:        r.nonce,
		Algorithms:   supportedAlgorithms,
	}

	if (r.till == time.Time{}) {
		r.till = time.Now().AddDate(0, 0, 1).UTC()
	}
	body.Till.FullBytes = mustMarshal(r.till, "generalized")
	body.RenewTill = r.till.AddDate(0, 0, 6).UTC()

	bodydata := mustMarshal(body, "")

	reqparam := ""
	req := kdcRequest{
		ProtoVersion: kerberosVersion,
		Body:         asn1.RawValue{FullBytes: bodydata},
		// MsgType and Preauth filled out below
	}

	if r.tgt != nil {
		// For TGS requests we stash an AP_REQ for the ticket granting
		// service (using the krbtgt) as a preauth.
		reqparam = tgsRequestParam
		req.MsgType = tgsRequestType

		calgo := r.tgt.key.SignAlgo(paTgsRequestChecksumKey)
		chk := mustSign(r.tgt.key, calgo, paTgsRequestChecksumKey, bodydata)

		auth := authenticator{
			ProtoVersion:   kerberosVersion,
			ClientRealm:    r.crealm,
			Client:         r.client,
			Microseconds:   r.time.Nanosecond() / 1000,
			SequenceNumber: r.seqnum,
			Time:           time.Unix(r.time.Unix(), 0).UTC(), // round to the nearest second
			Checksum:       checksumData{calgo, chk},
		}

		authdata := mustMarshal(auth, authenticatorParam)
		app := appRequest{
			ProtoVersion: kerberosVersion,
			MsgType:      appRequestType,
			Flags:        flagsToBitString(0),
			Ticket:       asn1.RawValue{FullBytes: r.tgt.ticket},
			Auth: encryptedData{
				Algo: r.tgt.key.EncryptAlgo(paTgsRequestKey),
				Data: r.tgt.key.Encrypt(nil, paTgsRequestKey, authdata),
			},
		}

		appdata := mustMarshal(app, appRequestParam)
		req.Preauth = []preauth{{paTgsRequest, appdata}}

	} else {
		reqparam = asRequestParam
		req.MsgType = asRequestType

		// For AS requests we add a PA-ENC-TIMESTAMP preauth if we
		// have a key spefied. We won't on the first request so that
		// we can get a preauth error with the salt to use.
		if r.ckey != nil {
			// Use the sequence number as the microseconds in the
			// timestamp so that each one is guarenteed to be unique
			tsdata := mustMarshal(encryptedTimestamp{r.time, int(r.seqnum % 1000000)}, "")
			algo := r.ckey.EncryptAlgo(paEncryptedTimestampKey)

			//jbs -- this needs modified to also check if first request or not?
			if (algo == cryptAES128SHA1 && len(r.salt) > 0) ||
				(algo == cryptAES256SHA1 && len(r.salt) > 0) ||
				(algo != cryptAES128SHA1 && algo != cryptAES256SHA1) {

				edata := r.ckey.Encrypt(r.salt, paEncryptedTimestampKey, tsdata)
				enc := mustMarshal(encryptedData{algo, r.ckvno, edata}, "")

				req.Preauth = []preauth{{paEncryptedTimestamp, enc}}
			}
		}
	}

	data := mustMarshal(req, reqparam)

	if r.proto == "tcp" {
		var bsz [4]byte
		binary.BigEndian.PutUint32(bsz[:], uint32(len(data)))
		mustWrite(r.sock, bsz[:])
	}

	if r.proto == "udp" && len(data) > maxUDPWrite {
		panic(io.ErrShortWrite)
	}

	mustWrite(r.sock, data)
	return nil
}

func (r *request) recvReply() (tkt *Ticket, err error) {
	defer recoverMust(&err)

	var data []byte

	switch r.proto {
	case "tcp":
		// TCP streams prepend a 32bit big endian size before each PDU
		bsz := [4]byte{}
		mustReadFull(r.sock, bsz[:])

		size := int(binary.BigEndian.Uint32(bsz[:]))

		if size > maxPDUSize {
			logging.Warn("PDU Size: %d", size)
		}
		must(0 <= size && size <= maxPDUSize)

		data = make([]byte, size)
		mustReadFull(r.sock, data)

	case "udp":
		// UDP PDUs are packed in individual frames
		data = make([]byte, maxPDUSize)
		data = mustRead(r.sock, data)

	default:
		panic(ErrInvalidProto(r.proto))
	}

	must(len(data) > 0)

	if (data[0] & 0x1F) == errorType {
		errmsg := errorMessage{}
		mustUnmarshal(data, &errmsg, errorParam)
		return nil, ErrRemote{&errmsg}
	}

	var msgtype, usage int
	var repparam, encparam string
	var key key

	if r.tgt != nil {
		repparam = tgsReplyParam
		msgtype = tgsReplyType
		key = r.tgt.key
		usage = tgsReplySessionKey
		encparam = encTgsReplyParam
	} else {
		repparam = asReplyParam
		msgtype = asReplyType
		key = r.ckey
		usage = asReplyClientKey
		encparam = encAsReplyParam
	}

	// Decode reply body
	rep := kdcReply{}
	mustUnmarshal(data, &rep, repparam)

	//Validate ticket requirements
	if rep.ProtoVersion != kerberosVersion {
		return nil, fmt.Errorf("proto version %d doesn't match kerberos version %d", rep.ProtoVersion, kerberosVersion)
	}
	if rep.MsgType != msgtype {
		return nil, fmt.Errorf("Msg type %d doesn't match expected %d", rep.MsgType, msgtype)
	}
	if rep.ClientRealm != r.crealm {
		return nil, fmt.Errorf("Client Realm %q doesn't match request realm %q", rep.ClientRealm, r.crealm)
	}

	if !nameEquals(rep.Client, r.client) {
		return nil, fmt.Errorf("Reply Client list %q doesn't contain request client %q", rep.Client, r.client)
	}

	// TGS doesn't use key versions as its using session keys
	if r.tgt == nil {
		// If we created the key from a keytab then we know the
		// version number, if we created it from plaintext then we use
		// the reply to find the key version

		if r.ckvno == 0 {
			r.ckvno = rep.Encrypted.KeyVersion
		} else {
			if r.ckvno != rep.Encrypted.KeyVersion {
				return nil, fmt.Errorf("request key value number %d doesn't match reply key value number %d", r.ckvno, rep.Encrypted.KeyVersion)
			}
		}
	}

	// Decode encrypted part
	enc := encryptedKdcReply{}
	edata := rep.Encrypted.Data
	if key != nil {
		edata = mustDecrypt(key, nil, rep.Encrypted.Algo, usage, rep.Encrypted.Data)
	}
	mustUnmarshal(edata, &enc, encparam)

	// The returned service may be different from the request. This
	// happens when we get a tgt of the next server to try.
	must(enc.Nonce == r.nonce && enc.ServiceRealm == r.srealm)
	key = mustLoadKey(enc.Key.Algo, enc.Key.Key)

	return &Ticket{
		cfg:       r.cfg,
		client:    r.client,
		crealm:    r.crealm,
		service:   enc.Service,
		srealm:    enc.ServiceRealm,
		ticket:    rep.Ticket.FullBytes,
		till:      enc.Till,
		renewTill: enc.RenewTill,
		authTime:  enc.AuthTime,
		startTime: enc.From,
		flags:     bitStringToFlags(enc.Flags),
		key:       key,
	}, nil
}

//Ticket is a kerberos ticket
type Ticket struct {
	cfg       *CredConfig
	client    principalName
	crealm    string
	service   principalName
	srealm    string
	ticket    []byte
	till      time.Time
	renewTill time.Time
	authTime  time.Time
	startTime time.Time
	flags     int
	key       key
}

//DefaultDial is the standard dialing behavior if no extra protocols are required
func DefaultDial(proto, realm string) (io.ReadWriteCloser, error) {
	if proto != "tcp" && proto != "udp" {
		return nil, ErrInvalidProto(proto)
	}

	_, addrs, err := net.LookupSRV("kerberos", proto, realm)

	if err != nil {
		_, addrs, err = net.LookupSRV("kerberos-master", proto, realm)
		if err != nil {
			return nil, err
		}
	}

	var sock net.Conn

	for _, a := range addrs {
		addr := net.JoinHostPort(a.Target, strconv.Itoa(int(a.Port)))
		sock, err = net.Dial(proto, addr)
		if err == nil {
			break
		}
	}

	if err != nil {
		return nil, err
	}

	if proto == "udp" {
		// For datagram connections, we retry up to three times, then give up
		sock.SetReadDeadline(time.Now().Add(udpReadTimeout))
	}

	return sock, nil
}

type timeoutError interface {
	Timeout() bool
}

// do performs an AS_REQ (r.ckey != nil) or TGS_REQ (r.tgt != nil) returning a
// new ticket
func (r *request) do() (tkt *Ticket, err error) {
	if ticketDialTCP {
		r.proto = "tcp"
	} else {
		r.proto = "udp"
	}
	r.sock = nil
	r.nonce = 0

	// Limit the number of retries before we give up and error out with the last error
	// For AES128 and AES256:
	//     first try should error out with 0x19 - KDC_ERR_PREAUTH_REQUIRED
	//     second try should error out on udp
	//     third try should succeed
	for i := 0; i < 3; i++ {
		if r.sock == nil {
			if r.sock, err = r.cfg.dial(r.proto, r.srealm); err != nil {
				break
			}
		}

		if r.nonce == 0 {
			if err = binary.Read(r.cfg.rand(), binary.BigEndian, &r.nonce); err != nil {
				break
			}
			if err = binary.Read(r.cfg.rand(), binary.BigEndian, &r.seqnum); err != nil {
				break
			}
			// Reduce the entropy of the nonce to 31 bits to ensure it fits in a 4
			// byte asn.1 value. Active directory seems to need this.
			r.nonce >>= 1
			r.time = r.cfg.now().UTC()
		}

		// TODO what error do we get if the tcp socket has been closed underneath us
		err = r.sendRequest()

		if r.proto == "udp" && err == io.ErrShortWrite {
			r.nonce = 0
			r.proto = "tcp"
			r.sock.Close()
			r.sock = nil
			continue
		} else if err != nil {
			break
		}

		tkt, err = r.recvReply()

		if err == nil {
			break
		} else if e, ok := err.(ErrRemote); ok && e.ErrorCode() == int(KDC_ERR_PREAUTH_REQUIRED) && len(r.salt) == 0 {
			d := e.ErrorData()
			var padata = make([]preauth, 0)
			mustUnmarshal(d, &padata, "")

			r.salt = findSaltFromPAData(padata)

			continue

		} else if e, ok := err.(ErrRemote); r.proto == "udp" && ok && e.ErrorCode() == int(KRB_ERR_RESPONSE_TOO_BIG) {
			r.nonce = 0
			r.proto = "tcp"
			r.sock.Close()
			r.sock = nil
			continue

		} else if e, ok := err.(timeoutError); r.proto == "udp" && ok && e.Timeout() {
			// Try again for UDP timeouts.  Reuse nonce, time, and
			// seqnum values so if the multiple requests end up at
			// the server, the server will ignore the retries as
			// replays.
			continue

		} else {
			break
		}
	}

	if r.sock != nil {
		r.sock.Close()
		r.sock = nil
	}

	return tkt, err
}

// Principal returns the principal of the service the ticket is for
func (t *Ticket) Principal() string {
	return composePrincipal(t.service)
}

// Realm returns the realm of the service the ticket is for
func (t *Ticket) Realm() string {
	return t.srealm
}

// ExpiryTime returns the time at which the ticket expires
func (t *Ticket) ExpiryTime() time.Time {
	return t.till
}

// GenerateTicket generates a local ticket that a client can use to
// authenticate against this credential.
//
// This is provided for loopback clients and unit tests, and SHOULD NOT be
// used outside of those cases. For all other cases, tickets should be
// requested through the KDC.
func (c *Credential) GenerateTicket(client, crealm string, cfg *TicketConfig) (rtkt *Ticket, rerr error) {
	defer recoverMust(&rerr)

	crealm = strings.ToUpper(crealm)

	if cfg == nil {
		cfg = &DefaultTicketConfig
	}

	if c.key == nil {
		return nil, ErrPassword
	}

	etype := c.key.EncryptAlgo(ticketKey)
	tkey := mustGenerateKey(etype, c.cfg.rand())
	till := cfg.Till
	now := c.cfg.now().UTC()

	// round down to the nearest millisecond as the wire protocol doesn't allow higher res
	now = now.Add(-(time.Duration(now.Nanosecond()) % time.Millisecond))

	if till.IsZero() {
		// a long way in the future
		till = now.Add(200 * 356 * 24 * time.Hour)
	}

	etkt := encryptedTicket{
		Flags: flagsToBitString(cfg.Flags),
		Key: encryptionKey{
			Algo: etype,
			Key:  tkey.Key(),
		},
		ClientRealm: crealm,
		Client:      splitPrincipal(client),
		AuthTime:    now,
		Till:        till,
	}

	etktdata := mustMarshal(etkt, encTicketParam)

	tkt := ticket{
		ProtoVersion: kerberosVersion,
		Realm:        c.realm,
		Service:      c.principal,
		Encrypted: encryptedData{
			Algo: c.key.EncryptAlgo(ticketKey),
			Data: c.key.Encrypt(nil, ticketKey, etktdata),
		},
	}

	tktdata := mustMarshal(tkt, ticketParam)

	return &Ticket{
		cfg:       c.cfg,
		client:    etkt.Client,
		crealm:    crealm,
		service:   c.principal,
		srealm:    c.realm,
		ticket:    tktdata,
		till:      till,
		authTime:  now,
		startTime: now,
		flags:     cfg.Flags,
		key:       tkey,
	}, nil
}

func (c *Credential) mustGenerateTicket(client, crealm string, cfg *TicketConfig) *Ticket {
	tkt, err := c.GenerateTicket(client, crealm, cfg)
	if err != nil {
		panic(err)
	}
	return tkt
}
