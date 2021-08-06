package kerb

/*
  #include "mitK5Helper.h"
  #include "krb5.h"
  #include "k5-int.h"
  #include "crypto_int.h"

  #cgo CFLAGS: -I../../krb5/krb5/src/include/ -I../../krb5/krb5/src/lib/crypto/krb/ -I../../krb5/krb5/src/lib/crypto/builtin/
  #cgo LDFLAGS: -L/usr/local/lib/ -lk5crypto -lkrb5
*/
import "C"

import (
	"bytes"
	"unsafe"

	logging "github.com/erock530/go.logging"
)

type aesHmac struct {
	key     []byte
	algo    int
	kvno    int
	krb5key C.krb5_keyblock
	//typedef struct _krb5_keyblock {
	//	  krb5_magic magic;
	//	  krb5_enctype enctype;
	//	  unsigned int length;
	//	  krb5_octet *contents; //unsigned char
	//} krb5_keyblock;
}

var (
	krb5enctypes = map[int]string{
		1:  "des-cbc-crc",
		2:  "des-cbc-md4",
		3:  "des-cbc-md5",
		7:  "des3-cbc-sha1",
		17: "aes128-cts-hmac-sha1-96",
		18: "aes256-cts-hmac-sha1-96",
		19: "aes128-cts-hmac-sha256-128",
		20: "aes256-cts-hmac-sha384-192",
		23: "arcfour-hmac",
		24: "arcfour-hmac-exp",
	}
)

func (a *aesHmac) EncryptAlgo(usage int) int {
	return a.algo
}

func (a *aesHmac) SignAlgo(usage int) int {
	logging.Debug("Choosing to sign with %d", usage)
	return usage
}

//I believe this function is already incorporated in the krb5_c_encrypt / krb5_c_decrypt
func (a *aesHmac) Sign(algo, usage int, data ...[]byte) ([]byte, error) {
	//this isn't currently required for AES, but this is probably defined
	//with the enctype (enctypes.c)... maybe krb5_hash_provider *hash.  For
	//aes256-cts-hmac-sha1-96, I'm guessing its: &krb5int_hash_sha1
	logging.Debug("Signing with unsupported AESHMAC")
	return []byte{}, nil
}

func (a *aesHmac) Key() []byte {
	return a.key
}

func (a *aesHmac) Decrypt(salt []byte, algo, usage int, data []byte) ([]byte, error) {
	//get/set krb5 context object
	ctx := C.getKrb5Context()

	//copy salt to cgo/krb5 object (Cipher state)
	var cipherState C.krb5_data
	if len(salt) > 0 {
		sChar := C.CString(string(salt))
		defer C.free(unsafe.Pointer(sChar))
		cipherState = C.krb5_data{magic: 0, length: C.uint(len(string(salt))), data: sChar}
	}

	//length for input / output pointers
	szData := len(data)

	//copy input
	cdata := C.CString(string(data))
	defer C.free(unsafe.Pointer(cdata))
	cipherdata := C.krb5_data{magic: 0, length: C.uint(szData), data: cdata}
	//kvno doens't seem to need to be accurate here
	indata := &C.krb5_enc_data{magic: 0, enctype: C.krb5_enctype(a.algo), kvno: C.krb5_kvno(a.kvno), ciphertext: cipherdata}

	//reserve memory for decrypted output data
	emptyChar := C.CString(string(""))
	defer C.free(unsafe.Pointer(emptyChar))
	odata := C.allocChar(emptyChar, C.uint(szData))
	defer C.free(unsafe.Pointer(odata))
	outdata := &C.krb5_data{magic: 0, length: C.uint(szData), data: odata}

	//krb5_c_decrypt(krb5_context context, const krb5_keyblock *keyblock,
	//    krb5_keyusage usage, const krb5_data *cipher_state,
	//    const krb5_enc_data *input, krb5_data *output)
	var krb5errcode C.krb5_error_code
	if len(salt) > 0 {
		krb5errcode, _ = C.krb5_c_decrypt(ctx, &a.krb5key, C.krb5_keyusage(usage), &cipherState, indata, outdata)
	} else {
		krb5errcode, _ = C.krb5_c_decrypt(ctx, &a.krb5key, C.krb5_keyusage(usage), nil, indata, outdata)
	}
	res := C.GoBytes(unsafe.Pointer(outdata.data), C.int(szData))

	if krb5errcode != 0 {
		logging.Errorf("failed to decrypt data: %d", krb5errcode)
		return []byte{}, nil
	}

	logging.Debug("krb5 aes decrypt, output: [%x]", res)
	return res, nil
}

func (a *aesHmac) Encrypt(salt []byte, usage int, data ...[]byte) []byte {
	//create krb5 context object
	ctx := C.getKrb5Context()

	//combine data to be encrypted
	allData := bytes.Join(data, nil)
	szAllData := len(allData)

	//set salt (Cipher state)
	var cipherState C.krb5_data
	if len(salt) > 0 {
		sChar := C.CString(string(salt))
		defer C.free(unsafe.Pointer(sChar))
		cipherState = C.krb5_data{magic: 0, length: C.uint(len(string(salt))), data: sChar}
	}

	//copy input to cgo/krb5 object
	csAllData := C.CString(string(allData))
	defer C.free(unsafe.Pointer(csAllData))
	indata := &C.krb5_data{magic: 0, length: C.uint(szAllData), data: csAllData}

	//reserve memory for *output

	//get length needed for cipher output; allocate encData with this len
	//krb5_error_code krb5_c_encrypt_length(krb5_contextÂ context,
	//                                      krb5_enctypeÂ enctype,
	//										size_tÂ inputlen,
	//										size_t *Â length)
	krb5enctype := C.krb5_enctype(a.algo)
	var szData C.size_t
	krb5errcode, _ := C.krb5_c_encrypt_length(ctx, krb5enctype, C.size_t(szAllData), &szData)
	if krb5errcode != 0 {
		logging.Warn("failed to allocate memory for encryption output: %d\n\n", krb5errcode)
		return []byte{}
	}

	//reserve memory for outcipher
	cipherStr := C.malloc(C.size_t(szData))
	defer C.free(unsafe.Pointer(cipherStr))
	cipherdata := C.krb5_data{magic: 0, length: C.uint(szData), data: (*C.char)(cipherStr)}

	//krb_enc_data -> magic (krb5_magic), enctype (krb5_enctype), kvno (krb5_kvno), ciphertext(krb5_data)
	//jbs -- kvno doens't seem to need to be accurate here
	outdata := &C.krb5_enc_data{magic: 0, enctype: krb5enctype, kvno: C.krb5_kvno(a.kvno), ciphertext: cipherdata}

	//krb5_error_code krb5_c_encrypt(      krb5_contextÂ context,    -- Library context
	//                               const krb5_keyblock*Â key,      -- Encryption key
	//		    					       krb5_keyusageÂ usage,     -- Key usage (see KRB5_KEYUSAGE types)
	//							     const krb5_data*Â cipher_state, -- Cipher state; specify NULL if not needed
	//							     const krb5_data*Â input,        -- Data to be encrypted
	//							           krb5_enc_data*Â output)   -- Encrypted data

	//When the initial AS-REQ is rejected, Windows replies with a salt.  I originally thought we
	//should encrypt with the salt, but its not currently used.
	//krb5errcode, _ = C.krb5_c_encrypt(ctx, &a.krb5key, C.krb5_keyusage(usage), &cipherState, indata, outdata)
	krb5errcode, _ = C.krb5_c_encrypt(ctx, &a.krb5key, C.krb5_keyusage(usage), nil, indata, outdata)
	if krb5errcode != 0 {
		logging.Warn("failed aes encryption: %d\n\n", krb5errcode)
		return []byte{}
	}

	res := C.GoBytes(unsafe.Pointer(outdata.ciphertext.data), C.int(szData))
	return res
}

func aesStringKey(password, salt string, keyLen int) *C.krb5_keyblock {
	krb5key := &C.krb5_keyblock{}

	csPass := C.CString(password)
	defer C.free(unsafe.Pointer(csPass))
	csSalt := C.CString(salt)
	defer C.free(unsafe.Pointer(csSalt))
	krb5string := &C.krb5_data{magic: 0, length: C.uint(len(password)), data: csPass}
	krb5salt := &C.krb5_data{magic: 0, length: C.uint(len(salt)), data: csSalt}
	krb5encType := aesEncType(keyLen)

	//krb lib defaults to iterations defined in implementation
	krb5errcode, _ := C.krb5_c_string_to_key(nil, krb5encType, krb5string, krb5salt, krb5key)
	if krb5errcode != 0 {
		logging.Warn("failed aes string_to_key: %d\n\n", krb5errcode)
	}

	return krb5key
}

func aesStringKeySpecifyIters(password, salt string, keyLen, nIters int) *C.krb5_keyblock {
	krb5key := &C.krb5_keyblock{} //storage for key

	csPass := C.CString(password)
	defer C.free(unsafe.Pointer(csPass))
	csSalt := C.CString(salt)
	defer C.free(unsafe.Pointer(csSalt))
	krb5string := &C.krb5_data{magic: 0, length: C.uint(len(password)), data: csPass}
	krb5salt := &C.krb5_data{magic: 0, length: C.uint(len(salt)), data: csSalt}
	krb5encType := aesEncType(keyLen)

	// set "params" (number of iterations)
	var paramStr = make([]C.uchar, 4)
	cRet := C.genParamString(C.int(nIters), C.int(len(paramStr)), &paramStr[0])
	if cRet != 0 {
		logging.Warn("failed to determine iterations needed for string_to_key")
		return krb5key
	}

	var cStr = make([]byte, 4)
	for i := 0; i < 4; i++ {
		cStr[i] = cStr[i] + byte(paramStr[i])
	}

	//specifiy iterations
	krb5params := &C.krb5_data{magic: 0, length: C.uint(len(paramStr)), data: (*C.char)(C.CBytes(cStr))}
	krb5errcode, _ := C.krb5_c_string_to_key_with_params(nil, krb5encType, krb5string, krb5salt, krb5params, krb5key)
	if krb5errcode != 0 {
		logging.Warn("failed string_to_key: %d", krb5errcode)
	}

	return krb5key
}

func aesEncType(keyLen int) C.krb5_enctype {
	if keyLen == 16 { // cryptAES128SHA1
		return C.krb5_enctype(0x0011)
	} else if keyLen == 32 { // cryptAES256SHA1
		return C.krb5_enctype(0x0012)
	} else { //default to RC4-HMAC
		return C.krb5_enctype(0x0017)
	}
}

func aesBytesToOctet(key []byte) *C.krb5_octet {
	csKey := C.CString(string(key))
	defer C.free(unsafe.Pointer(csKey))
	addr := C.bytesToOctet(csKey, C.uint(len(key)))
	return addr
}
