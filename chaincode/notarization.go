package main

import (
	"encoding/base64"
	"errors"
	"io/ioutil"
	"os"
	"strconv"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/hyperledger/fabric/core/crypto/primitives"
	"github.com/op/go-logging"
)

// For environment variables.
var myLogger = logging.MustGetLogger("notarization")

var sHandler = NewSignatureHandler()

// restResult defines the response payload for a general REST interface request.
type restResult struct {
	OK    string `protobuf:"bytes,1,opt,name=OK" json:"OK,omitempty"`
	Error string `protobuf:"bytes,2,opt,name=Error" json:"Error,omitempty"`
}

//NotarizationtChaincode APIs exposed to chaincode callers
type NotarizationtChaincode struct {
}

// sign signs a file with a given account ID
// args[0]: accountID
// args[1]: base64 of accountID's tcert
// args[2]: fileName
// args[3]: filePath
// args[4]: base64 of file content
// args[5]: sha512 hash of file content
// args[6]: base64 of signature of file
// args[7]: timestamp
func (t *NotarizationtChaincode) sign(stub *shim.ChaincodeStub, args []string) ([]byte, error) {
	myLogger.Debugf("+++++++++++++++++++++++++++++++++++ sign in chaincode +++++++++++++++++++++++++++++++++")
	myLogger.Debugf("sign args: %v", args)

	// parse arguments
	if len(args) != 8 {
		return nil, errors.New("Incorrect number of arguments. Expecting 0")
	}

	accountID := args[0]
	certString := args[1]
	fileName := args[2]
	filePath := args[3]

	fileContent, err := base64.StdEncoding.DecodeString(args[4])
	if err != nil {
		myLogger.Errorf("system error %v", err)
		return nil, errors.New("Failed decoding file content")
	}

	fileHash := args[5]

	fileSignature, err := base64.StdEncoding.DecodeString(args[6])
	if err != nil {
		myLogger.Errorf("system error %v", err)
		return nil, errors.New("Failed decoding file content")
	}

	timestr := args[7]
	timestamp, err := strconv.ParseInt(timestr, 10, 64)
	if err != nil {
		myLogger.Errorf("system error %v", err)
		return nil, errors.New("Failed parse timestamp")
	}

	err = os.MkdirAll(filePath, 0600)
	if err != nil {
		myLogger.Errorf("system error %v", err)
		return nil, errors.New("Failed MkdirAll")
	}
	err = ioutil.WriteFile(filePath+"/"+fileHash, fileContent, 0600)
	if err != nil {
		myLogger.Errorf("system error %v", err)
		return nil, errors.New("Failed parse timestamp")
	}

	// save state
	return nil, sHandler.submitSignature(stub,
		accountID,
		certString,
		fileName,
		filePath,
		fileHash,
		fileSignature,
		timestamp)
}

// verify verify a file signature with a given account ID
// args[0]: accountID
// args[1]: base64 of file content
// args[2]: sha512 hash of file content
// args[3]: base64 of signature of file
func (t *NotarizationtChaincode) verify(stub *shim.ChaincodeStub, args []string) ([]byte, error) {
	myLogger.Debugf("+++++++++++++++++++++++++++++++++++ verify in chaincode +++++++++++++++++++++++++++++++++")
	myLogger.Debugf("verify args: %v", args)

	// check arguments
	if len(args) != 4 {
		return nil, errors.New("Incorrect number of arguments. Expecting 4")
	}

	accountID := args[0]

	fileContent, err := base64.StdEncoding.DecodeString(args[1])
	if err != nil {
		myLogger.Errorf("system error %v", err)
		return nil, errors.New("Failed decoding file content")
	}

	fileSignature, err := base64.StdEncoding.DecodeString(args[3])
	if err != nil {
		myLogger.Errorf("system error %v", err)
		return nil, errors.New("Failed decoding file content")
	}

	fileHash := args[2]

	// get tcert from state
	certString, err := sHandler.getCertificate(stub, accountID, fileHash, fileSignature)
	if err != nil {
		myLogger.Errorf("system error %v", err)
		return nil, errors.New("Failed decoding file content")
	}

	certificate, err := primitives.PEMtoDER([]byte(certString))
	if err != nil {
		myLogger.Errorf("Error: PEMtoDER error: %v.", err)

		return nil, nil
	}

	// verify signature
	ok, err := stub.VerifySignature(
		certificate,
		fileSignature,
		fileContent,
	)
	if err != nil {
		myLogger.Errorf("Failed checking signature [%s]", err)
		return nil, err
	}
	if !ok {
		myLogger.Error("Invalid signature.")
	} else {
		myLogger.Info("Valid signature.")

		return []byte(args[3]), nil
	}

	return nil, nil
}

// verify verify a file signature with a given account ID
// args[0]: accountID
func (t *NotarizationtChaincode) getSignatures(stub *shim.ChaincodeStub, args []string) ([]byte, error) {
	myLogger.Debugf("+++++++++++++++++++++++++++++++++++ verify in chaincode +++++++++++++++++++++++++++++++++")
	myLogger.Debugf("verify args: %v", args)

	// check arguments
	if len(args) != 1 {
		return nil, errors.New("Incorrect number of arguments. Expecting 4")
	}

	accountID := args[0]

	// get signatures from state
	signatures, err := sHandler.getSignatures(stub, accountID)
	if err != nil {
		myLogger.Errorf("system error %v", err)
		return nil, errors.New("Failed decoding file content")
	}

	myLogger.Debugf("getSignatures(%v): %v", accountID, signatures)

	return signatures, nil
}

// ----------------------- CHAINCODE ----------------------- //

// Init initialization, this method will create asset despository in the chaincode state
func (t *NotarizationtChaincode) Init(stub *shim.ChaincodeStub, function string, args []string) ([]byte, error) {
	myLogger.Debugf("********************************Init****************************************")

	myLogger.Info("[NotarizationtChaincode] Init")
	if len(args) != 0 {
		return nil, errors.New("Incorrect number of arguments. Expecting 0")
	}

	return nil, sHandler.createTable(stub)
}

// Invoke  method is the interceptor of all invocation transactions, its job is to direct
// invocation transactions to intended APIs
func (t *NotarizationtChaincode) Invoke(stub *shim.ChaincodeStub, function string, args []string) ([]byte, error) {
	myLogger.Debugf("********************************Invoke****************************************")

	//	 Handle different functions
	if function == "sign" {
		// Sign file
		return t.sign(stub, args)
	} else if function == "verify" {
		// Verify file
		return t.verify(stub, args)
	}

	return nil, errors.New("Received unknown function invocation")
}

// Query method is the interceptor of all invocation transactions, its job is to direct
// query transactions to intended APIs, and return the result back to callers
func (t *NotarizationtChaincode) Query(stub *shim.ChaincodeStub, function string, args []string) ([]byte, error) {
	myLogger.Debugf("********************************Query****************************************")

	// Handle different functions
	if function == "verify" {
		return t.verify(stub, args)
	} else if function == "getSignatures" {
		return t.getSignatures(stub, args)
	}

	return nil, errors.New("Received unknown function query invocation with function " + function)
}

func main() {
	// chaincode won't read the yaml, so set the security leverl mannually
	primitives.SetSecurityLevel("SHA3", 256)
	err := shim.Start(new(NotarizationtChaincode))
	if err != nil {
		myLogger.Debugf("Error starting NotarizationtChaincode: %s", err)
	}
}
