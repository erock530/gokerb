package kerb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"runtime/debug"
	"strings"
	"time"

	"github.com/Novetta/asn1"
	logging "github.com/Novetta/go.logging"
)

//Errkrb is returned as part of the kerberos process
type Errkrb int

func (k Errkrb) Error() string {
	return k.String()
}

func (k Errkrb) String() string {
	msg := ""
	switch k {
	case KDC_ERR_NONE: // No error
		msg = "no error"
	case KDC_ERR_NAME_EXP: // Client's entry in database has expired
		msg = "Client entry expired"
	case KDC_ERR_SERVICE_EXP: // Server's entry in database has expired
		msg = "server entry expired"
	case KDC_ERR_BAD_PVNO: // Requested protocol version number not supported
		msg = "protocol version number not supported"
	case KDC_ERR_C_OLD_MAST_KVNO: // Client's key encrypted in old master key
		msg = "client's key encrypted in old master key"
	case KDC_ERR_S_OLD_MAST_KVNO: // Server's key encrypted in old master key
		msg = "server's key encrypted in old master key"
	case KDC_ERR_C_PRINCIPAL_UNKNOWN: // Client not found in Kerberos database
		msg = "client not found in Kerberos"
	case KDC_ERR_S_PRINCIPAL_UNKNOWN: // Server not found in Kerberos database
		msg = "server not found in Kerberos"
	case KDC_ERR_PRINCIPAL_NOT_UNIQUE: // Multiple principal entries in database
		msg = "Multiple principal entries"
	case KDC_ERR_NULL_KEY: // The client or server has a null key
		msg = "Client or server has null key"
	case KDC_ERR_CANNOT_POSTDATE: // Ticket not eligible for postdating
		msg = "Ticket not eligible for postdating"
	case KDC_ERR_NEVER_VALID: // Requested starttime is later than end time
		msg = "requested start time later than end time"
	case KDC_ERR_POLICY: // KDC policy rejects request
		msg = "KDC policy rejects request"
	case KDC_ERR_BADOPTION: // KDC cannot accommodate requested option
		msg = "KDC cannot accomodate requested option"
	case KDC_ERR_ETYPE_NOSUPP: // KDC has no support for encryption type
		msg = "KDC has no support for encryption type"
	case KDC_ERR_SUMTYPE_NOSUPP: // KDC has no support for checksum type
		msg = "KDC has no support for checksum type"
	case KDC_ERR_PADATA_TYPE_NOSUPP: // KDC has no support for padata type
		msg = "KDC has no support for padata type"
	case KDC_ERR_TRTYPE_NOSUPP: // KDC has no support for transited type
		msg = "KDC has no support for transited type"
	case KDC_ERR_CLIENT_REVOKED: // Clients credentials have been revoked
		msg = "clients credentials revoked"
	case KDC_ERR_SERVICE_REVOKED: // Credentials for server have been revoked
		msg = "server credentials revoked"
	case KDC_ERR_TGT_REVOKED: // TGT has been revoked
		msg = "TGT revoked"
	case KDC_ERR_CLIENT_NOTYET: // Client not yet valid; try again later
		msg = "Client not yet validl try again later"
	case KDC_ERR_SERVICE_NOTYET: // Server not yet valid; try again later
		msg = "server not yet valid; try again later"
	case KDC_ERR_KEY_EXPIRED: // Password has expired; change password to reset
		msg = "password exired; change password to reset"
	case KDC_ERR_PREAUTH_FAILED: // Pre-authentication information was invalid
		msg = "Pre-authentication was invalid"
	case KDC_ERR_PREAUTH_REQUIRED: // Additional pre-authentication required
		msg = "Additional pre-authentication required"
	case KDC_ERR_SERVER_NOMATCH: // Requested server and ticket don't match
		msg = "Server and ticket don't match"
	case KDC_ERR_MUST_USE_USER2USER: // Server principal valid for user2user only
		msg = "server principal valid for user2user only"
	case KDC_ERR_PATH_NOT_ACCEPTED: // KDC Policy rejects transited path
		msg = "KDC policy rejects transited path"
	case KDC_ERR_SVC_UNAVAILABLE: // A service is not available
		msg = "a service is not available"
	case KRB_AP_ERR_BAD_INTEGRITY: // Integrity check on decrypted field failed
		msg = "integreity check on decrypted field failed"
	case KRB_AP_ERR_TKT_EXPIRED: // Ticket expired
		msg = "ticket expired"
	case KRB_AP_ERR_TKT_NYV: // Ticket not yet valid
		msg = "ticket not yet valid"
	case KRB_AP_ERR_REPEAT: // Request is a replay
		msg = "request is a replay"
	case KRB_AP_ERR_NOT_US: // The ticket isn't for us
		msg = "ticket isn't for us"
	case KRB_AP_ERR_BADMATCH: // Ticket and authenticator don't match
		msg = "ticket and authenticator don't match"
	case KRB_AP_ERR_SKEW: // Clock skew too great
		msg = "clock skew too great"
	case KRB_AP_ERR_BADADDR: // Incorrect net address
		msg = "incorrect net address"
	case KRB_AP_ERR_BADVERSION: // Protocol version mismatch
		msg = "protocol version mismatch"
	case KRB_AP_ERR_MSG_TYPE: // Invalid msg type
		msg = "invalid msg type"
	case KRB_AP_ERR_MODIFIED: // Message stream modified
		msg = "message stream modified"
	case KRB_AP_ERR_BADORDER: // Message out of order
		msg = "message out of order"
	case KRB_AP_ERR_BADKEYVER: // Specified version of key is not available
		msg = "specified version of key is not available"
	case KRB_AP_ERR_NOKEY: // Service key not available
		msg = "service key not available"
	case KRB_AP_ERR_MUT_FAIL: // Mutual authentication failed
		msg = "mutual authentication failed"
	case KRB_AP_ERR_BADDIRECTION: // Incorrect message direction
		msg = "incorrect message direction"
	case KRB_AP_ERR_METHOD: // Alternative authentication method required
		msg = "alternative authentication method required"
	case KRB_AP_ERR_BADSEQ: // Incorrect sequence number in message
		msg = "incorrect sequence number in message"
	case KRB_AP_ERR_INAPP_CKSUM: // Inappropriate type of checksum in message
		msg = "inappropriate type of checksum in message"
	case KRB_AP_PATH_NOT_ACCEPTED: // Policy rejects transited path
		msg = "policy reject transited path"
	case KRB_ERR_RESPONSE_TOO_BIG: // Response too big for UDP; retry with TCP
		msg = "response too big for UDP; retry with tcp"
	case KRB_ERR_GENERIC: // Generic error (description in e-text)
		msg = "generic error"
	case KRB_ERR_FIELD_TOOLONG: // Field is too long for this implementation
		msg = "field is too long for this implementation"
	case KDC_ERROR_CLIENT_NOT_TRUSTED: // Reserved for PKINIT
		msg = "client not trusted (PKINIT)"
	case KDC_ERROR_KDC_NOT_TRUSTED: // Reserved for PKINIT
		msg = "KDC not trusted (PKINIT)"
	case KDC_ERROR_INVALID_SIG: // Reserved for PKINIT
		msg = "invalid sig (PKINIT)"
	case KDC_ERR_KEY_TOO_WEAK: // Reserved for PKINIT
		msg = "key too weak (PKINIT)"
	case KDC_ERR_CERTIFICATE_MISMATCH: // Reserved for PKINIT
		msg = "certificate mismatch (PKINIT)"
	case KRB_AP_ERR_NO_TGT: // No TGT available to validate USER-TO-USER
		msg = "no tgt available to validate user2user"
	case KDC_ERR_WRONG_REALM: // Reserved for future use
		msg = "wrong realm"
	case KRB_AP_ERR_USER_TO_USER_REQUIRED: // Ticket must be for USER-TO-USER
		msg = "ticket must be for user2user"
	case KDC_ERR_CANT_VERIFY_CERTIFICATE: // Reserved for PKINIT
		msg = "can't verify certificate(PKINIT)"
	case KDC_ERR_INVALID_CERTIFICATE: // Reserved for PKINIT
		msg = "invalid certificate (PKINIT)"
	case KDC_ERR_REVOKED_CERTIFICATE: // Reserved for PKINIT
		msg = "revoked certificate (PKINIT)"
	case KDC_ERR_REVOCATION_STATUS_UNKNOWN: // Reserved for PKINIT
		msg = "revocation status unknown (PKINIT)"
	case KDC_ERR_REVOCATION_STATUS_UNAVAILABLE: // Reserved for PKINIT
		msg = "revocation status unavailable (PKINIT)"
	case KDC_ERR_CLIENT_NAME_MISMATCH: // Reserved for PKINIT
		msg = "client name mismatch (PKINIT)"
	case KDC_ERR_KDC_NAME_MISMATCH: // Reserved for PKINIT
		msg = "KDC name mismatch (PKINIT)"
	default:
		msg = fmt.Sprintf("%d", k)
	}
	return msg
}

// Remote error codes
const (
	KDC_ERR_NONE                 = Errkrb(iota) // No error
	KDC_ERR_NAME_EXP                            // Client's entry in database has expired
	KDC_ERR_SERVICE_EXP                         // Server's entry in database has expired
	KDC_ERR_BAD_PVNO                            // Requested protocol version number not supported
	KDC_ERR_C_OLD_MAST_KVNO                     // Client's key encrypted in old master key
	KDC_ERR_S_OLD_MAST_KVNO                     // Server's key encrypted in old master key
	KDC_ERR_C_PRINCIPAL_UNKNOWN                 // Client not found in Kerberos database
	KDC_ERR_S_PRINCIPAL_UNKNOWN                 // Server not found in Kerberos database
	KDC_ERR_PRINCIPAL_NOT_UNIQUE                // Multiple principal entries in database
	KDC_ERR_NULL_KEY                            // The client or server has a null key
	KDC_ERR_CANNOT_POSTDATE                     // Ticket not eligible for postdating
	KDC_ERR_NEVER_VALID                         // Requested starttime is later than end time
	KDC_ERR_POLICY                              // KDC policy rejects request
	KDC_ERR_BADOPTION                           // KDC cannot accommodate requested option
	KDC_ERR_ETYPE_NOSUPP                        // KDC has no support for encryption type
	KDC_ERR_SUMTYPE_NOSUPP                      // KDC has no support for checksum type
	KDC_ERR_PADATA_TYPE_NOSUPP                  // KDC has no support for padata type
	KDC_ERR_TRTYPE_NOSUPP                       // KDC has no support for transited type
	KDC_ERR_CLIENT_REVOKED                      // Clients credentials have been revoked
	KDC_ERR_SERVICE_REVOKED                     // Credentials for server have been revoked
	KDC_ERR_TGT_REVOKED                         // TGT has been revoked
	KDC_ERR_CLIENT_NOTYET                       // Client not yet valid; try again later
	KDC_ERR_SERVICE_NOTYET                      // Server not yet valid; try again later
	KDC_ERR_KEY_EXPIRED                         // Password has expired; change password to reset
	KDC_ERR_PREAUTH_FAILED                      // Pre-authentication information was invalid
	KDC_ERR_PREAUTH_REQUIRED                    // Additional pre-authentication required
	KDC_ERR_SERVER_NOMATCH                      // Requested server and ticket don't match
	KDC_ERR_MUST_USE_USER2USER                  // Server principal valid for user2user only
	KDC_ERR_PATH_NOT_ACCEPTED                   // KDC Policy rejects transited path
	KDC_ERR_SVC_UNAVAILABLE                     // A service is not available
	_
	KRB_AP_ERR_BAD_INTEGRITY // Integrity check on decrypted field failed
	KRB_AP_ERR_TKT_EXPIRED   // Ticket expired
	KRB_AP_ERR_TKT_NYV       // Ticket not yet valid
	KRB_AP_ERR_REPEAT        // Request is a replay
	KRB_AP_ERR_NOT_US        // The ticket isn't for us
	KRB_AP_ERR_BADMATCH      // Ticket and authenticator don't match
	KRB_AP_ERR_SKEW          // Clock skew too great
	KRB_AP_ERR_BADADDR       // Incorrect net address
	KRB_AP_ERR_BADVERSION    // Protocol version mismatch
	KRB_AP_ERR_MSG_TYPE      // Invalid msg type
	KRB_AP_ERR_MODIFIED      // Message stream modified
	KRB_AP_ERR_BADORDER      // Message out of order
	_
	KRB_AP_ERR_BADKEYVER     // Specified version of key is not available
	KRB_AP_ERR_NOKEY         // Service key not available
	KRB_AP_ERR_MUT_FAIL      // Mutual authentication failed
	KRB_AP_ERR_BADDIRECTION  // Incorrect message direction
	KRB_AP_ERR_METHOD        // Alternative authentication method required
	KRB_AP_ERR_BADSEQ        // Incorrect sequence number in message
	KRB_AP_ERR_INAPP_CKSUM   // Inappropriate type of checksum in message
	KRB_AP_PATH_NOT_ACCEPTED // Policy rejects transited path
	KRB_ERR_RESPONSE_TOO_BIG // Response too big for UDP; retry with TCP
	_
	_
	_
	_
	_
	_
	_
	KRB_ERR_GENERIC                       // Generic error (description in e-text)
	KRB_ERR_FIELD_TOOLONG                 // Field is too long for this implementation
	KDC_ERROR_CLIENT_NOT_TRUSTED          // Reserved for PKINIT
	KDC_ERROR_KDC_NOT_TRUSTED             // Reserved for PKINIT
	KDC_ERROR_INVALID_SIG                 // Reserved for PKINIT
	KDC_ERR_KEY_TOO_WEAK                  // Reserved for PKINIT
	KDC_ERR_CERTIFICATE_MISMATCH          // Reserved for PKINIT
	KRB_AP_ERR_NO_TGT                     // No TGT available to validate USER-TO-USER
	KDC_ERR_WRONG_REALM                   // Reserved for future use
	KRB_AP_ERR_USER_TO_USER_REQUIRED      // Ticket must be for USER-TO-USER
	KDC_ERR_CANT_VERIFY_CERTIFICATE       // Reserved for PKINIT
	KDC_ERR_INVALID_CERTIFICATE           // Reserved for PKINIT
	KDC_ERR_REVOKED_CERTIFICATE           // Reserved for PKINIT
	KDC_ERR_REVOCATION_STATUS_UNKNOWN     // Reserved for PKINIT
	KDC_ERR_REVOCATION_STATUS_UNAVAILABLE // Reserved for PKINIT
	KDC_ERR_CLIENT_NAME_MISMATCH          // Reserved for PKINIT
	KDC_ERR_KDC_NAME_MISMATCH             // Reserved for PKINIT
)

// Address type
const (
	ipv4 = 2
	ipv6 = 24
)

// Message types
const (
	asRequestType = 10 + iota
	asReplyType
	tgsRequestType
	tgsReplyType
	appRequestType
	appReplyType
	errorType = 30
)

// Name types
const (
	principalNameType = 1 + iota
	serviceInstanceType
	serviceHostType
)

// Preauth types
const (
	paTgsRequest = 1 + iota
	paEncryptedTimestamp
	paPasswordSalt
	_
	_
	_
	_
	_
	_
	_
	paETypeInfo
	_
	_
	_
	_
	_
	_
	_
	paETypeInfo2
)

// Encryption algorithms
const (
	cryptDesCbcMd4      = 2
	cryptDesCbcMd5      = 3
	cryptAES128SHA1     = 17
	cryptAES256SHA1     = 18
	cryptAES128SHA256   = 19
	cryptAES256SHA384   = 20
	cryptRc4Hmac        = 23
	signAES128SHA196    = 15
	signAES256SHA196    = 16
	signAES128SHA256128 = 19
	signAES256SHA384192 = 20
	signMd4             = 2
	signMd4Des          = 3
	signMd5             = 7
	signMd5Des          = 8
	signRc4Hmac         = -138
	signGssFake         = 0x8003

	cryptGssDes     = 0x0000
	cryptGssRc4Hmac = 0x1000
	cryptGssNone    = 0xFFFF

	signGssMd5Des  = 0x0000
	signGssDes     = 0x0200
	signGssRc4Hmac = 0x1100
)

// Key usage values
const (
	paEncryptedTimestampKey = iota + 1
	ticketKey
	asReplyClientKey
	tgsRequestAuthSessionKey
	tgsRequestAuthSubKey
	paTgsRequestChecksumKey
	paTgsRequestKey
	tgsReplySessionKey
	tgsReplySubKey
	appRequestAuthChecksumKey
	appRequestAuthKey
	appReplyEncryptedKey
	privKey
	credKey
	safeChecksumKey
	_
	_
	_
	_
	_
	_
	_
	gssWrapSeal
	gssWrapSign

	gssSequenceNumber = -1
)

const (
	kerberosVersion  = 5
	applicationClass = 0x40
	udpReadTimeout   = 3 * time.Second
	maxUDPWrite      = 1400      // TODO: figure out better way of doing this
	maxGSSWrapRead   = 64 * 1024 // TODO: remove this as a limitation
	maxPDUSize       = 8 * 1024
)

//ErrProtocol is returned if the request is malformed or incorrect
type ErrProtocol string

func (e ErrProtocol) String() string {
	if e == "" {
		e = "kerb: protocol error"
	}
	return string(e)
}
func (e ErrProtocol) Error() string {
	if e == "" {
		e = "kerb: protocol error"
	}
	return string(e)
}

//ErrParse is returned if a request can't be parsed
type ErrParse string

func (e ErrParse) Error() string {
	if e == "" {
		e = "kerb: parse error"
	}
	return string(e)
}

var (
	ErrAuthLoop          = errors.New("kerb: auth loop")
	ErrPassword          = errors.New("kerb: can't renew the main krbtgt ticket as the password is unknown")
	ErrNoCommonAlgorithm = errors.New("kerb: no common algorithm")

	supportedAlgorithms = []int{cryptRc4Hmac, cryptDesCbcMd5, cryptDesCbcMd4, cryptAES128SHA1, cryptAES256SHA1}

	ticketParam        = "application,explicit,tag:1"
	authenticatorParam = "application,explicit,tag:2"
	encTicketParam     = "application,explicit,tag:3"
	asRequestParam     = "application,explicit,tag:10"
	asReplyParam       = "application,explicit,tag:11"
	tgsRequestParam    = "application,explicit,tag:12"
	tgsReplyParam      = "application,explicit,tag:13"
	appRequestParam    = "application,explicit,tag:14"
	appReplyParam      = "application,explicit,tag:15"
	seqReplyParam      = "application,explicit,tag:16"
	encAsReplyParam    = "application,explicit,tag:25"
	encTgsReplyParam   = "application,explicit,tag:26"
	encAppReplyParam   = "application,explicit,tag:27"
	errorParam         = "application,explicit,tag:30"

	negTokenInitParam  = "explicit,tag:0"
	negTokenReplyParam = "explicit,tag:1"

	gssKrb5Oid    = asn1.ObjectIdentifier([]int{1, 2, 840, 113554, 1, 2, 2})
	gssOldKrb5Oid = asn1.ObjectIdentifier([]int{1, 3, 5, 1, 5, 2})
	gssMsKrb5Oid  = asn1.ObjectIdentifier([]int{1, 2, 840, 48018, 1, 2, 2})
	gssSpnegoOid  = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 5, 5, 2})
)

type ErrRemote struct {
	msg *errorMessage
}

func (e ErrRemote) ErrorData() []byte {
	return e.msg.ErrorData
}

func (e ErrRemote) ErrorCode() int {
	return e.msg.ErrorCode
}

func (e ErrRemote) Error() string {
	return fmt.Sprintf("kerb: remote error %d %s %s", e.msg.ErrorCode,
		Errkrb(e.msg.ErrorCode), e.msg.ErrorText)
}

type ErrInvalidProto string

func (s ErrInvalidProto) Error() string {
	return "kerb: invalid protocol - " + string(s)
}

type ErrTicket struct {
	reason string
}

func (s ErrTicket) Error() string {
	return "kerb: invalid ticket - " + s.reason
}

// Flags for tkt.Connect and tkt.Accept
const (
	MutualAuth = 1 << iota
	SASLAuth
	NoConfidentiality
	NoSecurity
	RequireConfidentiality
	RequireIntegrity
)

const (
	// default of negTokenReply.State so it appears when State is not set
	// in the asn1 marshalled stream
	spnegoUseContext = iota - 1
	spnegoAccepted
	spnegoIncomplete
	spnegoReject
	spnegoRequestMIC
)

// gss token types
const (
	// From RFC1964
	gssAppRequest    = 0x0100
	gssGetMIC        = 0x0101
	gssDeleteContext = 0x0102
	gssAppReply      = 0x0200
	gssWrap          = 0x0201
	gssAppError      = 0x0300
)

// App request flags
const (
	useSessionKey = 1 << 30
	mutualAuth    = 1 << 29
)

// gss app request flags - found in the gss fake checksum in the AP-REQ
// authenticator
const (
	gssDelegation = 1 << iota
	gssMutual
	gssReplay
	gssSequence
	gssConfidential
	gssIntegrity
	gssAnonymous
	gssProtectionReady
	gssTransferable
)

// gss sasl flags - first byte of the 4 bytes gss wrap exchange after the AP-REQ
const (
	saslNoSecurity = 1 << iota
	saslIntegrity
	saslConfidential
)

type principalName struct {
	Type  int      `asn1:"explicit,tag:0"`
	Parts []string `asn1:"general,explicit,tag:1"`
}

type encryptedData struct {
	Algo       int    `asn1:"explicit,tag:0"`
	KeyVersion int    `asn1:"optional,explicit,tag:1"`
	Data       []byte `asn1:"explicit,tag:2"`
}

type encryptionKey struct {
	Algo int    `asn1:"explicit,tag:0"`
	Key  []byte `asn1:"explicit,tag:1"`
}

type ticket struct {
	ProtoVersion int           `asn1:"explicit,tag:0"`
	Realm        string        `asn1:"general,explicit,tag:1"`
	Service      principalName `asn1:"explicit,tag:2"`
	Encrypted    encryptedData `asn1:"explicit,tag:3"`
}

type transitedEncoding struct {
	Type     int    `asn1:"explicit,tag:0"`
	Contents []byte `asn1:"explicit,tag:1"`
}

// Known as authorization in the RFCs
type restriction struct {
	Type int    `asn1:"explicit,tag:0"`
	Data []byte `asn1:"explicit,tag:1"`
}

type address struct {
	Type    int    `asn1:"explicit,tag:0"`
	Address []byte `asn1:"explicit,tag:1"`
}

type preauth struct {
	Type int    `asn1:"explicit,tag:1"`
	Data []byte `asn1:"optional,explicit,tag:2"`
}

type checksumData struct {
	Algo int    `asn1:"explicit,tag:0"`
	Data []byte `asn1:"explicit,tag:1"`
}

type encryptedTimestamp struct {
	Time         time.Time `asn1:"generalized,explicit,tag:0"`
	Microseconds int       `asn1:"optional,explicit,tag:1"`
}

type eTypeInfo struct {
	EType int    `asn1:"explicit,tag:0"`
	Salt  []byte `asn1:"explicit,tag:1,optional"`
}

type eTypeInfo2 struct {
	EType int    `asn1:"explicit,tag:0"`
	Salt  string `asn1:"explicit,tag:1,optional"`
}

type encryptedTicket struct {
	Flags        asn1.BitString    `asn1:"explicit,tag:0"`
	Key          encryptionKey     `asn1:"explicit,tag:1"`
	ClientRealm  string            `asn1:"general,explicit,tag:2"`
	Client       principalName     `asn1:"explicit,tag:3"`
	Transited    transitedEncoding `asn1:"explicit,tag:4"`
	AuthTime     time.Time         `asn1:"generalized,explicit,tag:5"`
	From         time.Time         `asn1:"generalized,optional,explicit,tag:6"`
	Till         time.Time         `asn1:"generalized,explicit,tag:7"`
	RenewTill    time.Time         `asn1:"generalized,optional,explicit,tag:8"`
	Addresses    []address         `asn1:"optional,explicit,tag:9"`
	Restrictions []restriction     `asn1:"optional,explicit,tag:10"`
}

type kdcRequest struct {
	ProtoVersion int           `asn1:"explicit,tag:1"`
	MsgType      int           `asn1:"explicit,tag:2"`
	Preauth      []preauth     `asn1:"optional,explicit,tag:3"`
	Body         asn1.RawValue `asn1:"explicit,tag:4"`
}

type kdcRequestBody struct {
	Flags             asn1.BitString  `asn1:"explicit,tag:0"`
	Client            principalName   `asn1:"optional,explicit,tag:1"`
	ServiceRealm      string          `asn1:"general,explicit,tag:2"`
	Service           principalName   `asn1:"optional,explicit,tag:3"`
	From              time.Time       `asn1:"generalized,optional,explicit,tag:4"`
	Till              asn1.RawValue   `asn1:"explicit,tag:5"`
	RenewTill         time.Time       `asn1:"generalized,optional,explicit,tag:6"`
	Nonce             uint32          `asn1:"explicit,tag:7"`
	Algorithms        []int           `asn1:"explicit,tag:8"`
	Addresses         []address       `asn1:"optional,explicit,tag:9"`
	Authorization     encryptedData   `asn1:"optional,explicit,tag:10"`
	AdditionalTickets []asn1.RawValue `asn1:"optional,explicit,tag:11"`
}

type kdcReply struct {
	ProtoVersion int           `asn1:"explicit,tag:0"`
	MsgType      int           `asn1:"explicit,tag:1"`
	Preauth      []preauth     `asn1:"optional,explicit,tag:2"`
	ClientRealm  string        `asn1:"general,explicit,tag:3"`
	Client       principalName `asn1:"explicit,tag:4"`
	Ticket       asn1.RawValue `asn1:"explicit,tag:5"`
	Encrypted    encryptedData `asn1:"explicit,tag:6"`
}

type lastRequest struct {
	Type int       `asn1:"explicit,tag:0"`
	Time time.Time `asn1:"generalized,explicit,tag:1"`
}

type encryptedKdcReply struct {
	Key             encryptionKey  `asn1:"explicit,tag:0"`
	LastRequests    []lastRequest  `asn1:"explicit,tag:1"`
	Nonce           uint32         `asn1:"explicit,tag:2"`
	ClientKeyExpiry time.Time      `asn1:"generalized,optional,explicit,tag:3"`
	Flags           asn1.BitString `asn1:"explicit,tag:4"`
	AuthTime        time.Time      `asn1:"generalized,explicit,tag:5"`
	From            time.Time      `asn1:"generalized,optional,explicit,tag:6"`
	Till            time.Time      `asn1:"generalized,explicit,tag:7"`
	RenewTill       time.Time      `asn1:"generalized,optional,explicit,tag:8"`
	ServiceRealm    string         `asn1:"general,explicit,tag:9"`
	Service         principalName  `asn1:"explicit,tag:10"`
	Addresses       []address      `asn1:"optional,explicit,tag:11"`
}

type appRequest struct {
	ProtoVersion int            `asn1:"explicit,tag:0"`
	MsgType      int            `asn1:"explicit,tag:1"`
	Flags        asn1.BitString `asn1:"explicit,tag:2"`
	Ticket       asn1.RawValue  `asn1:"explicit,tag:3"`
	Auth         encryptedData  `asn1:"explicit,tag:4"`
}

type authenticator struct {
	ProtoVersion   int           `asn1:"explicit,tag:0"`
	ClientRealm    string        `asn1:"general,explicit,tag:1"`
	Client         principalName `asn1:"explicit,tag:2"`
	Checksum       checksumData  `asn1:"optional,explicit,tag:3"`
	Microseconds   int           `asn1:"explicit,tag:4"`
	Time           time.Time     `asn1:"generalized,explicit,tag:5"`
	SubKey         encryptionKey `asn1:"optional,explicit,tag:6"`
	SequenceNumber uint32        `asn1:"optional,explicit,tag:7"`
	Restrictions   []restriction `asn1:"optional,explicit,tag:8"`
}

type appReply struct {
	ProtoVersion int           `asn1:"explicit,tag:0"`
	MsgType      int           `asn1:"explicit,tag:1"`
	Encrypted    encryptedData `asn1:"explicit,tag:2"`
}

type encryptedAppReply struct {
	ClientTime         time.Time     `asn1:"generalized,explicit,tag:0"`
	ClientMicroseconds int           `asn1:"explicit,tag:1"`
	SubKey             encryptionKey `asn1:"optional,explicit,tag:2"`
	SequenceNumber     uint32        `asn1:"optional,explicit,tag:3"`
}

type errorMessage struct {
	ProtoVersion       int           `asn1:"explicit,tag:0"`
	MsgType            int           `asn1:"explicit,tag:1"`
	ClientTime         time.Time     `asn1:"generalized,optional,explicit,tag:2"`
	ClientMicroseconds int           `asn1:"optional,explicit,tag:3"`
	ServerTime         time.Time     `asn1:"generalized,explicit,tag:4"`
	ServerMicroseconds int           `asn1:"explicit,tag:5"`
	ErrorCode          int           `asn1:"explicit,tag:6"`
	ClientRealm        string        `asn1:"general,optional,explicit,tag:7"`
	Client             principalName `asn1:"optional,explicit,tag:8"`
	ServiceRealm       string        `asn1:"general,explicit,tag:9"`
	Service            principalName `asn1:"explicit,tag:10"`
	ErrorText          string        `asn1:"general,optional,explicit,tag:11"`
	ErrorData          []byte        `asn1:"optional,explicit,tag:12"`
}

type negTokenInit struct {
	Mechanisms []asn1.ObjectIdentifier `asn1:"explicit,tag:0"`
	Token      []byte                  `asn1:"explicit,tag:2,optional"`
}

type negTokenReply struct {
	State     int                   `asn1:"optional,explicit,tag:0,default:-1"`
	Mechanism asn1.ObjectIdentifier `asn1:"optional,explicit,tag:1"`
	Response  []byte                `asn1:"optional,explicit,tag:2"`
}

func nameEquals(a, b principalName) bool {
	// Note two principals with different types but the same components
	// are considered equivalent
	if len(a.Parts) != len(b.Parts) {
		return false
	}

	for i, ap := range a.Parts {
		if ap != b.Parts[i] {
			return false
		}
	}

	return true
}

// splitPrincipal splits the principal (sans realm) in p into the split on
// wire format.
func splitPrincipal(p string) (r principalName) {
	// Per the RFC: When a name implies no information other than its
	// uniqueness at a particular time, the name type PRINCIPAL SHOULD be
	// used.
	r.Type = principalNameType
	r.Parts = strings.Split(p, "/")
	return
}

// composePrincipal converts the on wire principal format to a composed
// string.
func composePrincipal(n principalName) string {
	return strings.Join(n.Parts, "/")
}

func bitStringToFlags(s asn1.BitString) int {
	y := [4]byte{}
	for i, b := range s.Bytes {
		y[i] = b
	}
	return int(binary.BigEndian.Uint32(y[:]))
}

func findSaltFromPAData(padata []preauth) []byte {
	var salt = make([]byte, 0)

	if len(padata) > 0 {
		for _, p := range padata {
			if p.Type == paETypeInfo2 {
				logging.Debug("p.Type: %v", p.Type)
				logging.Debug("p.Data: %v", p.Data)
				var eidata = make([]eTypeInfo2, 0)
				mustUnmarshal(p.Data, &eidata, "")

				for _, ei := range eidata {
					if ei.EType == cryptAES128SHA1 || ei.EType == cryptAES256SHA1 {
						salt = []byte(ei.Salt)
						break
					}
				}

				break
			}
		}
	}

	return salt
}

func flagsToBitString(flags int) (s asn1.BitString) {
	s.Bytes = make([]byte, 4)
	s.BitLength = 32
	binary.BigEndian.PutUint32(s.Bytes, uint32(flags))
	return
}

func must(cond bool) {
	if !cond {
		logging.Errorf("Must Panic. Stack:\n%s", debug.Stack())
		panic(ErrProtocol("Must panic condition failed"))
	}
}

func mustMarshal(val interface{}, params string) []byte {
	data, err := asn1.MarshalWithParams(val, params)
	if err != nil {
		panic(err)
	}
	return data
}

func mustUnmarshal(data []byte, val interface{}, params string) {
	if _, err := asn1.UnmarshalWithParams(data, val, params); err != nil {
		panic(err)
	}
}

func mustRead(r io.Reader, buf []byte) []byte {
	n, err := r.Read(buf)
	if err != nil {
		panic(err)
	}
	return buf[:n]
}

func mustReadFull(r io.Reader, buf []byte) {
	if _, err := io.ReadFull(r, buf); err != nil {
		panic(err)
	}
}

func mustWrite(w io.Writer, buf []byte) {
	if _, err := w.Write(buf); err != nil {
		panic(err)
	}
}

func recoverMust(perr *error) {
	v := recover()
	if v == nil {
		return
	}

	err, ok := v.(error)
	if !ok {
		panic(v)
	}

	*perr = err
}
