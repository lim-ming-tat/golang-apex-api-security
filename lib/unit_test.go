package lib

import (
	"crypto/rsa"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

var BASEPATH = "../../github.com/GovTechSG/test-suites-apex-api-security/"

func Test_defaultParams(t *testing.T) {
	executeTest(t, BASEPATH+"testData/defaultParams.json", func(param *TestParam) (string, error) {
		result, err := getDefaultParam(param.APIParam)

		// timestamp value not set in input param, update the expected result after getDefaultParam set the value
		if param.APIParam.Timestamp == "" {
			param.setExpectedResult(fmt.Sprintf(param.getExpectedResult(), (ArrayNameValuePair{nameValue: result}).Search(strings.ToLower(param.APIParam.AuthPrefix)+"_timestamp")))
		}

		// nonce value not set in input param, update the expected result after getDefaultParam set the value
		if param.APIParam.Nonce == "" {
			param.setExpectedResult(fmt.Sprintf(param.getExpectedResult(), (ArrayNameValuePair{nameValue: result}).Search(strings.ToLower(param.APIParam.AuthPrefix)+"_nonce")))
		}

		paramString := (ArrayNameValuePair{nameValue: result}).Stringify()

		return paramString, err
	})
}

func Test_l1Signature(t *testing.T) {
	executeTest(t, BASEPATH+"testData/getL1Signature.json", func(param *TestParam) (string, error) {
		return getHMACSignature(param.Message, param.APIParam.Secret)
	})
}

func Test_L2Signature(t *testing.T) {
	executeTest(t, BASEPATH+"testData/getL2Signature.json", func(param *TestParam) (string, error) {
		result := ""

		privateKey, err := getPrivateKeyFromPEM(BASEPATH+param.APIParam.PrivateCertFileName, param.APIParam.Passphrase)
		if err == nil {
			result, err = getRSASignature(param.Message, privateKey)
		}

		return result, err
	})
}

func Test_getSignatureBaseString(t *testing.T) {
	executeTest(t, BASEPATH+"testData/getSignatureBaseString.json", func(param *TestParam) (string, error) {
		return getSignatureBaseString(param.APIParam)
	})
}

func Test_getSignatureToken(t *testing.T) {
	executeTest(t, BASEPATH+"testData/getSignatureToken.json", func(param *TestParam) (string, error) {
		dynamicTimestamp := false
		if param.APIParam.Timestamp == "" {
			dynamicTimestamp = true
		}
		dynamicNonce := false
		if param.APIParam.Nonce == "" {
			dynamicNonce = true
		}

		// reset the cert folder...
		param.APIParam.PrivateCertFileName = BASEPATH + param.APIParam.PrivateCertFileName

		result, err := getSignatureToken(&param.APIParam)

		if err == nil {
			if dynamicTimestamp && dynamicNonce {
				//t.Logf(">>> timestamp %s, nonce %s <<<", param.APIParam.Timestamp, param.APIParam.Nonce)

				param.setExpectedResult(fmt.Sprintf(param.getExpectedResult(), param.APIParam.Nonce, param.APIParam.Timestamp, param.APIParam.Signature))
			} else if dynamicTimestamp {
				//t.Logf(">>> timestamp %s <<<", param.APIParam.Timestamp)

				param.setExpectedResult(fmt.Sprintf(param.getExpectedResult(), param.APIParam.Timestamp, param.APIParam.Signature))
			} else if dynamicNonce {
				//t.Logf(">>> nonce %s <<<", param.APIParam.Nonce)

				param.setExpectedResult(fmt.Sprintf(param.getExpectedResult(), param.APIParam.Nonce, param.APIParam.Signature))
			}
		}

		return result, err
	})
}

func Test_verifyL1Signature(t *testing.T) {
	executeTest(t, BASEPATH+"testData/verifyL1Signature.json", func(param *TestParam) (string, error) {
		result, err := VerifyL1Signature(param.Message, param.APIParam.Secret, param.APIParam.Signature)
		return strconv.FormatBool(result), err
	})
}

func Test_verifyL2Signature(t *testing.T) {
	executeTest(t, BASEPATH+"testData/verifyL2Signature.json", func(param *TestParam) (string, error) {
		//t.Logf(">>> filetype %s -- %s <<<", filepath.Ext(param.PublicCertFileName), param.PublicCertFileName)
		result := false
		var publicKey *rsa.PublicKey
		var err error

		fileExtension := strings.ToLower(filepath.Ext(BASEPATH + param.PublicCertFileName))

		if fileExtension == ".cer" {
			publicKey, err = getPublicKeyFromCert(BASEPATH + param.PublicCertFileName)
		} else if fileExtension == ".pem" {
			//publicKey, err = getPublicKeyFromPEM(param.PublicCertFileName)
			publicKey, err = getPublicKeyFromCert(BASEPATH + param.PublicCertFileName)
		} else if fileExtension == ".key" {
			publicKey, err = getPublicKeyFromPEM(BASEPATH + param.PublicCertFileName)
		} else {
			t.Errorf("\nnot supported file tyep::: %s", BASEPATH+param.PublicCertFileName)
		}

		if err == nil {
			result, err = VerifyL2Signature(param.Message, publicKey, param.APIParam.Signature)
		}

		return strconv.FormatBool(result), err
	})
}

func Test_HTTPCall(t *testing.T) {
	executeTest(t, BASEPATH+"testData/httpCall.json", func(param *TestParam) (string, error) {
		// reset the cert folder...
		param.APIParam.PrivateCertFileName = BASEPATH + param.APIParam.PrivateCertFileName

		return makeHTTPCall(*param)
	})
}
