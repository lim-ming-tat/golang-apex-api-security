package lib

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// APIParam ()
type APIParam struct {
	Realm        string `json:"realm"`
	AppID        string `json:"appId"`
	AuthPrefix   string `json:"authPrefix"`
	Secret       string `json:"secret"`
	InvokeURL    string `json:"invokeUrl"`
	SignatureURL string `json:"signatureUrl"`

	HTTPMethod string `json:"httpMethod"`
	Signature  string `json:"signature"`

	PrivateCertFileName string `json:"privateCertFileName"`
	Passphrase          string
	SignatureMethod     string `json:"signatureMethod"`
	Nonce               string `json:"nonce"`
	Timestamp           string `json:"timestamp"`
	Version             string `json:"version"`

	QueryString map[string]interface{} `json:"queryString"`
	FormData    map[string]interface{} `json:"formData"`
}

func generateNonce() (string, error) {
	nonceSize := 14

	nonce := make([]byte, nonceSize, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(nonce), nil
}

func getDefaultParam(baseProps APIParam) ([][]string, error) {
	var paramsArray [][]string

	lowerAuthPrefix := strings.ToLower(baseProps.AuthPrefix)
	prefixedAppID := lowerAuthPrefix + "_app_id"
	prefixedNonce := lowerAuthPrefix + "_nonce"
	prefixedSignatureMethod := lowerAuthPrefix + "_signature_method"
	prefixedTimestamp := lowerAuthPrefix + "_timestamp"
	prefixedVersion := lowerAuthPrefix + "_version"

	paramsArray = append(paramsArray, []string{prefixedAppID, baseProps.AppID})

	if baseProps.Nonce == "" {
		nonce, _ := generateNonce()
		paramsArray = append(paramsArray, []string{prefixedNonce, nonce})
	} else {
		paramsArray = append(paramsArray, []string{prefixedNonce, baseProps.Nonce})
	}

	if baseProps.SignatureMethod == "" {
		var signatureMethod string
		if baseProps.Secret == "" {
			signatureMethod = "SHA256withRSA"
		} else {
			signatureMethod = "HMACSHA256"
		}
		paramsArray = append(paramsArray, []string{prefixedSignatureMethod, signatureMethod})
	} else {
		paramsArray = append(paramsArray, []string{prefixedSignatureMethod, baseProps.SignatureMethod})
	}
	if baseProps.Timestamp == "" {
		paramsArray = append(paramsArray, []string{prefixedTimestamp, strconv.FormatInt(time.Now().UnixNano(), 10)[0:13]})
	} else {
		paramsArray = append(paramsArray, []string{prefixedTimestamp, baseProps.Timestamp})
	}

	if baseProps.Version == "" {
		paramsArray = append(paramsArray, []string{prefixedVersion, "1.0"})
	} else {
		paramsArray = append(paramsArray, []string{prefixedVersion, baseProps.Version})
	}

	return paramsArray, nil
}

func getSignatureBaseString(baseProps APIParam) (string, error) {
	siteURL, err := url.Parse(baseProps.SignatureURL)
	if err != nil {
		return "", err
	}

	if siteURL.Scheme != "http" && siteURL.Scheme != "https" {
		return "", fmt.Errorf("not supported URL scheme(%s), only http and https allow", siteURL.Scheme)
	}

	// Remove port from url
	signatureURL := fmt.Sprintf("%v://%v%v", siteURL.Scheme, siteURL.Hostname(), siteURL.Path)

	defaultParams, err := getDefaultParam(baseProps)

	// extract queryString from baseProps
	queryStringArray := paramsStringify(baseProps.QueryString)
	defaultParams = append(defaultParams, queryStringArray...)

	// transfer queryString from url for sorting
	query := siteURL.Query()
	siteURL.RawQuery = query.Encode()
	queryMap, _ := url.ParseQuery(siteURL.RawQuery)
	for key, value := range queryMap {
		for _, u := range value {
			defaultParams = append(defaultParams, []string{key, u})
		}
	}

	formDataArray := paramsStringify(baseProps.FormData)
	defaultParams = append(defaultParams, formDataArray...)

	paramString := ""
	sort.Slice(defaultParams[:], func(i, j int) bool {
		for x := range defaultParams[i] {
			if defaultParams[i][x] == defaultParams[j][x] {
				continue
			}
			return defaultParams[i][x] < defaultParams[j][x]
		}
		return false
	})

	paramString = ArrayNameValuePair{defaultParams}.Stringify()

	sigBaseString := strings.ToUpper(baseProps.HTTPMethod) + "&" + signatureURL + paramString

	return sigBaseString, nil
}

// ArrayNameValuePair ()
type ArrayNameValuePair struct {
	nameValue [][]string
}

// Search ()
func (param ArrayNameValuePair) Search(name string) string {
	for _, value := range param.nameValue {
		if value[0] == name {
			return value[1]
		}
	}

	return ""
}

// Stringify ()
func (param ArrayNameValuePair) Stringify() string {
	paramString := ""

	for _, value := range param.nameValue {
		if value[1] == "" {
			paramString = fmt.Sprintf("%v&%v", paramString, value[0])
		} else {
			paramString = fmt.Sprintf("%v&%v=%v", paramString, value[0], value[1])
		}
	}

	return paramString
}

func paramsStringify(params map[string]interface{}) [][]string {
	var paramArray [][]string

	for key, value := range params {
		switch v := value.(type) {
		case string:
			paramArray = append(paramArray, []string{key, v})
		case bool:
			paramArray = append(paramArray, []string{key, strconv.FormatBool(v)})
		case float64:
			paramArray = append(paramArray, []string{key, strconv.FormatFloat(v, 'f', -1, 64)})
		case []interface{}:
			paramInterfaceArray := paramArrayStringify(key, v)
			paramArray = append(paramArray, paramInterfaceArray...)
		default: // support string, bool, float64 and array only, all other datatype will be ignore
			paramArray = append(paramArray, []string{key, ""})
			//return nil, fmt.Errorf("paramsStringify - params fields data type for '%s' of type '%s' not supported", key, reflect.TypeOf(v).Kind())
		}
	}

	return paramArray
}
func paramArrayStringify(key string, params []interface{}) [][]string {
	var paramArray [][]string

	for _, value := range params {
		switch v := value.(type) {
		case string:
			paramArray = append(paramArray, []string{key, v})
		case bool:
			paramArray = append(paramArray, []string{key, strconv.FormatBool(v)})
		case float64:
			paramArray = append(paramArray, []string{key, strconv.FormatFloat(v, 'f', -1, 64)})
		default: // support string, bool, float64 only, all other datatype will be ignore
			paramArray = append(paramArray, []string{key, ""})
			//return nil, fmt.Errorf("paramArrayStringify - params fields data type for '%s' of type '%s' not supported", key, reflect.TypeOf(v).Kind())
		}
	}
	return paramArray
}

func getHMACSignature(message string, secret string) (string, error) {
	if message == "" || secret == "" {
		return "", fmt.Errorf("message and secret must not be null or empty!")
	}

	messageHMAC := hmac.New(sha256.New, []byte(secret))
	messageHMAC.Write([]byte(message))

	return base64.StdEncoding.EncodeToString(messageHMAC.Sum(nil)), nil
}

// VerifyL1Signature ()
func VerifyL1Signature(message string, secret string, signature string) (bool, error) {
	return verifyHMACSignature(message, secret, signature)
}

func verifyHMACSignature(message string, secret string, signature string) (bool, error) {
	newSignature, err := getHMACSignature(message, secret)
	if err != nil {
		return false, err
	}

	return newSignature == signature, nil
}

func getPrivateKeyFromPEM(privateKeyFileName string, passphrase string) (privateKey *rsa.PrivateKey, err error) {
	// Read the private key
	pemData, err := ioutil.ReadFile(privateKeyFileName)
	if err != nil {
		return nil, err
	}

	// Extract the PEM-encoded data block
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, err
	}

	if got, want := block.Type, "RSA PRIVATE KEY"; got == want {
		//log.Fatalf("unknown key type %q, want %q", got, want)
		if passphrase != "" {
			decBlock, err := x509.DecryptPEMBlock(block, []byte(passphrase))
			if err != nil {
				//log.Fatalf("error decrypting pem file: %s", err.Error())
				return nil, err
			}
			block.Bytes = decBlock
		}
		// Decode the RSA private key
		parseResult, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			//log.Fatalf("bad private key: %s", err)
			return nil, err
		}

		privateKey = parseResult
	}

	if got, want := block.Type, "PRIVATE KEY"; got == want {
		// Decode the RSA private key
		parseResult, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			//log.Fatalf("bad private key: %s", err)
			return nil, err
		}

		// cast to correct type, rsaPrivateKey
		privateKey = parseResult.(*rsa.PrivateKey)
	}

	if privateKey == nil {
		return nil, fmt.Errorf("failed to get private key from %v", privateKeyFileName)
	}

	return privateKey, nil
}

//https://golang.org/src/crypto/rsa/example_test.go?m=text
func signPKCS1v15(rsaPrivateKey *rsa.PrivateKey, message string) (base64Signature string, err error) {
	// crypto/rand.Reader is a good source of entropy for blinding the RSA
	// operation.

	byteMessage := []byte(message)

	// Only small messages can be signed directly; thus the hash of a
	// message, rather than the message itself, is signed. This requires
	// that the hash function be collision resistant. SHA-256 is the
	// least-strong hash function that should be used for this at the time
	// of writing (2016).
	hashed := sha256.Sum256(byteMessage)

	signature, err := rsa.SignPKCS1v15(nil, rsaPrivateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", err
	}

	base64Signature = base64.StdEncoding.EncodeToString(signature)

	return base64Signature, nil
}

//func getRSASignature(message string, pemFileName string, passphrase string) (string, error) {
func getRSASignature(message string, privateKey *rsa.PrivateKey) (string, error) {
	if message == "" || privateKey == nil {
		return "", fmt.Errorf("message and privateKey must not be null or empty")
	}
	/*
		privateKey, err := getPrivateKeyFromPEM(pemFileName, passphrase)
		if err != nil {
			return "", err
		}

		if privateKey == nil {
			return "", fmt.Errorf("failed to get private key from %v", pemFileName)
		}
	*/
	base64Signature, err := signPKCS1v15(privateKey, message)
	if err != nil {
		return "", err
	}

	return base64Signature, nil
}

// GetAuthorizationToken ()
func GetAuthorizationToken(reqProps APIParam) (string, error) {
	return getSignatureToken(&reqProps)
}

func getSignatureToken(reqProps *APIParam) (string, error) {
	// Input validation since this is the public facing API
	if reqProps.AuthPrefix == "" || reqProps.AppID == "" || reqProps.SignatureURL == "" || reqProps.HTTPMethod == "" {
		return "", fmt.Errorf("One or more required parameters are missing!")
	}

	authPrefix := strings.ToLower(reqProps.AuthPrefix)

	if reqProps.Secret == "" {
		reqProps.SignatureMethod = "SHA256withRSA"
	} else {
		reqProps.SignatureMethod = "HMACSHA256"
	}

	if reqProps.Nonce == "" {
		reqProps.Nonce, _ = generateNonce()
	}

	if reqProps.Timestamp == "" {
		reqProps.Timestamp = strconv.FormatInt(time.Now().UnixNano(), 10)[0:13]
	}

	baseString, err := getSignatureBaseString(*reqProps)
	if err != nil {
		return "", err
	}

	if reqProps.SignatureMethod == "HMACSHA256" {
		reqProps.Signature, err = getHMACSignature(baseString, reqProps.Secret)
		if err != nil {
			return "", err
		}
	} else {
		privateKey, err := getPrivateKeyFromPEM(reqProps.PrivateCertFileName, reqProps.Passphrase)
		if err != nil {
			return "", err
		}

		reqProps.Signature, err = getRSASignature(baseString, privateKey)
		if err != nil {
			return "", err
		}
	}

	signatureToken := strings.Title(authPrefix) + " realm=\"" + reqProps.Realm + "\""
	defaultParams, _ := getDefaultParam(*reqProps)
	defaultParams = append(defaultParams, []string{authPrefix + "_signature", reqProps.Signature})

	for _, value := range defaultParams {
		signatureToken = signatureToken + ", " + value[0] + "=\"" + value[1] + "\""
	}

	return signatureToken, nil
}

func getPublicKeyFromPEM(publicKeyFileName string) (*rsa.PublicKey, error) {
	// Read the private key
	pemData, err := ioutil.ReadFile(publicKeyFileName)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	/*
		switch pub := pub.(type) {
		case *rsa.PublicKey:
			fmt.Println("pub is of type RSA:", pub)
		case *dsa.PublicKey:
			fmt.Println("pub is of type DSA:", pub)
		case *ecdsa.PublicKey:
			fmt.Println("pub is of type ECDSA:", pub)
		default:
			panic("unknown type of public key")
		}
	*/

	return pub.(*rsa.PublicKey), nil
}

func getPublicKeyFromCert(publicKeyFileName string) (*rsa.PublicKey, error) {
	// Read the private key
	pemData, err := ioutil.ReadFile(publicKeyFileName)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %v", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %s", err.Error())
	}

	return cert.PublicKey.(*rsa.PublicKey), nil
}

// VerifyL2Signature ()
func VerifyL2Signature(message string, rsaPublicKey *rsa.PublicKey, base64Signature string) (bool, error) {
	return verifyPKCS1v15(message, rsaPublicKey, base64Signature)
}

func verifyPKCS1v15(message string, rsaPublicKey *rsa.PublicKey, base64Signature string) (bool, error) {
	// convert string to []byte
	byteMessage := []byte(message)

	// convert base64 to []byte
	signature, _ := base64.StdEncoding.DecodeString(base64Signature)

	// Only small messages can be signed directly; thus the hash of a
	// message, rather than the message itself, is signed. This requires
	// that the hash function be collision resistant. SHA-256 is the
	// least-strong hash function that should be used for this at the time
	// of writing (2016).
	hashed := sha256.Sum256(byteMessage)

	err := rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		return false, err
	}

	// signature is a valid signature of message from the public key.
	return true, nil
}
