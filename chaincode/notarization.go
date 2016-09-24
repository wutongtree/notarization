package main

import (
	"encoding/base64"
	"errors"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/hyperledger/fabric/core/crypto/primitives"
	"github.com/op/go-logging"
)

// For environment variables.
var (
	logger = logging.MustGetLogger("notarization.chaincode")

	sHandler = NewSignatureHandler()
)

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
// args[1]: base64 of accountID's ecert
// args[2]: fileName
// args[3]: md5sum hash of file content
// args[4]: base64 of signature of file
// args[5]: timestamp
func (t *NotarizationtChaincode) sign(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	logger.Debugf("+++++++++++++++++++++++++++++++++++ sign in chaincode +++++++++++++++++++++++++++++++++")
	logger.Debugf("sign args: %v", args)

	// parse arguments
	if len(args) != 6 {
		return nil, errors.New("Incorrect number of arguments. Expecting 6")
	}

	accountID := args[0]
	certString := args[1]
	fileName := args[2]
	fileHash := args[3]

	fileSignature, err := base64.StdEncoding.DecodeString(args[4])
	if err != nil {
		logger.Errorf("system error %v", err)
		return nil, errors.New("Failed decoding file content")
	}

	timestr := args[5]

	// save state
	return nil, sHandler.submitSignature(stub,
		accountID,
		certString,
		fileName,
		fileHash,
		fileSignature,
		timestr)
}

// verify verify a file signature with a given account ID
// args[0]: accountID
// args[1]: base64 of file content
// args[2]: md5sum hash of file content
// args[3]: base64 of signature of file
func (t *NotarizationtChaincode) verify(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	logger.Debugf("+++++++++++++++++++++++++++++++++++ verify in chaincode +++++++++++++++++++++++++++++++++")

	// check arguments
	if len(args) != 4 {
		return nil, errors.New("Incorrect number of arguments. Expecting 4")
	}

	accountID := args[0]

	fileContent, err := base64.StdEncoding.DecodeString(args[1])
	if err != nil {
		logger.Errorf("system error %v", err)
		return nil, errors.New("Failed decoding file content")
	}

	fileSignature, err := base64.StdEncoding.DecodeString(args[3])
	if err != nil {
		logger.Errorf("system error %v", err)
		return nil, errors.New("Failed decoding file content")
	}

	fileHash := args[2]

	// get tcert from state
	certString, err := sHandler.getCertificate(stub, accountID, fileHash, fileSignature)
	if err != nil {
		logger.Errorf("system error %v", err)
		return nil, errors.New("Failed decoding file content")
	}
	certificate := []byte(certString)

	// verify signature
	ok, err := stub.VerifySignature(
		certificate,
		fileSignature,
		fileContent,
	)
	if err != nil {
		logger.Errorf("Failed checking signature [%s]", err)
		return nil, err
	}
	if !ok {
		logger.Error("Invalid signature.")
	} else {
		logger.Info("Valid signature.")

		return []byte(args[3]), nil
	}

	return nil, nil
}

// verify verify a file signature with a given account ID
// args[0]: accountID
func (t *NotarizationtChaincode) getSignatures(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	logger.Debugf("+++++++++++++++++++++++++++++++++++ getSignatures in chaincode +++++++++++++++++++++++++++++++++")
	logger.Debugf("getSignatures args: %v", args)

	// check arguments
	if len(args) != 1 {
		return nil, errors.New("Incorrect number of arguments. Expecting 4")
	}

	accountID := args[0]

	// get signatures from state
	signatures, err := sHandler.getSignatures(stub, accountID)
	if err != nil {
		logger.Errorf("system error %v", err)
		return nil, errors.New("Failed decoding file content")
	}

	logger.Debugf("getSignatures(%v): %v", accountID, signatures)

	return signatures, nil
}

// ----------------------- CHAINCODE ----------------------- //

// Init initialization, this method will create asset despository in the chaincode state
func (t *NotarizationtChaincode) Init(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	logger.Debugf("********************************Init****************************************")

	logger.Info("[NotarizationtChaincode] Init")
	if len(args) != 0 {
		return nil, errors.New("Incorrect number of arguments. Expecting 0")
	}

	return nil, sHandler.createTable(stub)
}

// Invoke  method is the interceptor of all invocation transactions, its job is to direct
// invocation transactions to intended APIs
func (t *NotarizationtChaincode) Invoke(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	logger.Debugf("********************************Invoke****************************************")

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
func (t *NotarizationtChaincode) Query(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	logger.Debugf("********************************Query****************************************")

	logger.Debugf("Notarizationt: function=%v, args=%v", function, args)

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
		logger.Debugf("Error starting NotarizationtChaincode: %s", err)
	}
}
