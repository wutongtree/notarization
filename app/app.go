package main

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"net/http"

	"github.com/spf13/cobra"

	"github.com/gocraft/web"
	"github.com/hyperledger/fabric/core/util"
	pb "github.com/hyperledger/fabric/protos"
	"github.com/spf13/viper"
)

// --------------- AppCmd ---------------

// AppCmd returns the cobra command for APP
func AppCmd() *cobra.Command {
	return appStartCmd
}

var appStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Starts the app.",
	Long:  `Starts a app that interacts with the network.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return serve(args)
	},
}

// --------------- Structs ---------------
// following defines structs used for communicate with clients

// restResult defines the response payload for a general REST interface request.
type restResult struct {
	OK    string `protobuf:"bytes,1,opt,name=OK" json:"OK,omitempty"`
	Error string `protobuf:"bytes,2,opt,name=Error" json:"Error,omitempty"`
}

// loginRequest is a object to establish security between client and app.
type loginRequest struct {
	EnrollID     string `protobuf:"bytes,1,opt,name=enrollId" json:"enrollId,omitempty"`
	EnrollSecret string `protobuf:"bytes,2,opt,name=enrollSecret" json:"enrollSecret,omitempty"`
}

// signRequest is a object to sign a file
type signRequest struct {
	EnrollID    string `protobuf:"bytes,1,opt,name=enrollId" json:"enrollId,omitempty"`
	EnrollToken string `protobuf:"bytes,2,opt,name=enrollToken" json:"enrollToken,omitempty"`
	FileName    string `protobuf:"bytes,2,opt,name=fileName" json:"fileName,omitempty"`
	FileContent string `protobuf:"bytes,3,opt,name=fileContent" json:"fileContent,omitempty"`
	FileHash    string `protobuf:"bytes,4,opt,name=fileHash" json:"fileHash,omitempty"`
}

// verifyRequest is a object to verify a signature
type verifyRequest struct {
	EnrollID    string `protobuf:"bytes,1,opt,name=enrollId" json:"enrollId,omitempty"`
	Signer      string `protobuf:"bytes,2,opt,name=signer" json:"signer,omitempty"`
	FileContent string `protobuf:"bytes,3,opt,name=fileContent" json:"fileContent,omitempty"`
	FileHash    string `protobuf:"bytes,4,opt,name=fileHash" json:"fileHash,omitempty"`
	Signature   string `protobuf:"bytes,5,opt,name=signature" json:"signature,omitempty"`
}

// signatureRequest is a object to signatures
type signatureRequest struct {
	EnrollID    string `protobuf:"bytes,1,opt,name=enrollId" json:"enrollId,omitempty"`
	EnrollToken string `protobuf:"bytes,2,opt,name=enrollToken" json:"enrollToken,omitempty"`
}

// signatureResponse
type signatureEntity struct {
	FileHash      string `json:"fileHash,omitempty"`
	FileName      string `json:"fileName,omitempty"`
	FileSignature string `json:"fileSignature,omitempty"`
	Timestamp     string `json:"timestamp,omitempty"`
}

type signatureResponse struct {
	OK         string            `json:"OK,omitempty"`
	Error      string            `json:"Error,omitempty"`
	Signatures []signatureEntity `json:"signatures,omitempty"`
}

// following defines structs used for communicate with peers

// certsResult defines the response payload for the GetTransactionCert REST interface request.
type certsResult struct {
	OK string
}

// chaincodeRequest defines request for invoke chaincode
type chaincodeRequest struct {
	Jsonrpc string           `protobuf:"bytes,1,opt,name=jsonrpc" json:"jsonrpc,omitempty"`
	Method  string           `protobuf:"bytes,2,opt,name=method" json:"method,omitempty"`
	Params  pb.ChaincodeSpec `protobuf:"bytes,3,opt,name=params" json:"params,omitempty"`
	ID      string           `protobuf:"bytes,4,opt,name=id" json:"id,omitempty"`
}

// chaincodeResult defines data from chaincode invoke
type chaincodeResult struct {
	Status  string `protobuf:"bytes,1,opt,name=status" json:"status,omitempty"`
	Message string `protobuf:"bytes,2,opt,name=message" json:"message,omitempty"`
}

// chaincodeResponse defines response from chaincode invoke
type chaincodeResponse struct {
	Jsonrpc string          `protobuf:"bytes,1,opt,name=jsonrpc" json:"jsonrpc,omitempty"`
	Result  chaincodeResult `protobuf:"bytes,2,opt,name=result" json:"result,omitempty"`
	ID      string          `protobuf:"bytes,3,opt,name=id" json:"id,omitempty"`
}

// --------------- NotarizationAPP ---------------

// NotarizationAPP defines the Notarization REST service object.
type NotarizationAPP struct {
}

func buildNotarizationRouter() *web.Router {
	router := web.New(NotarizationAPP{})

	// Add middleware
	router.Middleware((*NotarizationAPP).SetResponseType)

	// Add routes
	router.Post("/login", (*NotarizationAPP).login)
	router.Post("/sign", (*NotarizationAPP).sign)
	router.Post("/verify", (*NotarizationAPP).verify)
	router.Post("/getSignatures", (*NotarizationAPP).getSignatures)

	// Add not found page
	router.NotFound((*NotarizationAPP).NotFound)

	return router
}

// SetResponseType is a middleware function that sets the appropriate response
// headers. Currently, it is setting the "Content-Type" to "application/json" as
// well as the necessary headers in order to enable CORS for Swagger usage.
func (s *NotarizationAPP) SetResponseType(rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	rw.Header().Set("Content-Type", "application/json")

	// Enable CORS
	rw.Header().Set("Access-Control-Allow-Origin", "*")
	rw.Header().Set("Access-Control-Allow-Headers", "accept, content-type")

	next(rw, req)
}

// NotFound returns a custom landing page when a given hyperledger end point
// had not been defined.
func (s *NotarizationAPP) NotFound(rw web.ResponseWriter, r *web.Request) {
	rw.WriteHeader(http.StatusNotFound)
	json.NewEncoder(rw).Encode(restResult{Error: "Notarization endpoint not found."})
}

// login confirms the account and secret password of the client with the
// CA and stores the enrollment certificate and key in the Devops server.
func (s *NotarizationAPP) login(rw web.ResponseWriter, req *web.Request) {
	encoder := json.NewEncoder(rw)

	// Decode the incoming JSON payload
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: err.Error()})
		logger.Errorf("Error: %s", err)

		return
	}

	var loginRequest loginRequest
	err = json.Unmarshal(body, &loginRequest)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: err.Error()})
		logger.Errorf("Register Error: %s", err)

		return
	}

	// Check that the enrollId and enrollSecret are not left blank.
	if (loginRequest.EnrollID == "") || (loginRequest.EnrollSecret == "") {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "enrollId and enrollSecret may not be blank."})
		logger.Error("Error: enrollId and enrollSecret may not be blank.")

		return
	}

	_, err = initCryptoClient(loginRequest.EnrollID, loginRequest.EnrollSecret)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: fmt.Sprintf("Login error: %v", err)})
		logger.Errorf("Login error: %v", err)

		return
	}

	rw.WriteHeader(http.StatusOK)
	encoder.Encode(restResult{OK: fmt.Sprintf("Login successful for user '%s'.", loginRequest.EnrollID)})
	logger.Infof("Login successful for user '%s'.\n", loginRequest.EnrollID)

	return
}

// sign confirms the enrollmentID and secret password of the client with the
// CA and stores the enrollment certificate and key in the Devops server.
func (s *NotarizationAPP) sign(rw web.ResponseWriter, req *web.Request) {
	encoder := json.NewEncoder(rw)

	// Decode the incoming JSON payload
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: err.Error()})
		logger.Errorf("Error: %s", err)

		return
	}

	var signRequest signRequest
	err = json.Unmarshal(body, &signRequest)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: err.Error()})
		logger.Errorf("Sign Error: %s", err)

		return
	}

	// Check that the enrollId and enrollSecret are not left blank.
	if (signRequest.EnrollID == "") || (signRequest.EnrollToken == "") {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "enrollId and enrollSecret may not be blank."})
		logger.Error("Error: enrollId and enrollSecret may not be blank.")

		return
	}

	// file hash
	fileContent, err := base64.StdEncoding.DecodeString(signRequest.FileContent)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "enrollId and enrollSecret may not be blank."})
		logger.Error("Error: enrollId and enrollSecret may not be blank.")

		return
	}
	md5sum := md5.Sum(fileContent)
	fileHash := fmt.Sprintf("%02x", md5sum)
	logger.Infof(" *** md5sum: %v ***", md5sum)
	logger.Infof(" *** fileHash: %v ***", fileHash)
	logger.Infof(" *** funcHash: %v ***", signRequest.FileHash)
	if fileHash != strings.ToLower(signRequest.FileHash) {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "fileHash not match."})
		logger.Error("Error: fileHash not match.")

		return
	}

	// Get the client
	client, err := initCryptoClient(signRequest.EnrollID, "")
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: fmt.Sprintf("Login error: %v", err)})
		logger.Errorf("Login error: %v", err)

		return
	}
	enCertHandler, err := client.GetEnrollmentCertificateHandler()
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "GetEnrollmentCertificateHandler error."})
		logger.Error("Error: GetEnrollmentCertificateHandler error.")

		return
	}

	// Get signing certificate
	eCertDER := enCertHandler.GetCertificate()
	certString := string(eCertDER)

	// Get the signature
	signature, err := enCertHandler.Sign(fileContent)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "Sign error."})
		logger.Error("Error: Sign error.")

		return
	}

	signaturestr := base64.StdEncoding.EncodeToString(signature)

	// Verify: no need to verify
	err = enCertHandler.Verify(signature, fileContent)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "Sign error."})
		logger.Error("Error: Sign error.")

		return
	}

	location, _ := time.LoadLocation("Asia/Chongqing")
	timestr := time.Now().In(location).String()

	// Prepare spec and submit
	args := []string{
		"sign",
		signRequest.EnrollID,
		certString,
		signRequest.FileName,
		signRequest.FileHash,
		signaturestr,
		timestr}

	chaincodeInput := &pb.ChaincodeInput{
		Args: util.ToChaincodeArgs(args...),
	}

	spec := &pb.ChaincodeSpec{
		Type:                 1,
		ChaincodeID:          &pb.ChaincodeID{Name: chaincodeName},
		CtorMsg:              chaincodeInput,
		ConfidentialityLevel: confidentialityLevel,
	}

	chaincodeInvocationSpec := &pb.ChaincodeInvocationSpec{ChaincodeSpec: spec}

	// Get the Transaction cert
	txCertHandler, err := client.GetTCertificateHandlerNext()
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "Sign error."})
		logger.Error("Error: Sign error.")

		return
	}
	txHandler, err := txCertHandler.GetTransactionHandler()
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "Sign error."})
		logger.Error("Error: Sign error.")

		return
	}

	// Now create the Transactions message and send to Peer.
	transaction, err := txHandler.NewChaincodeExecute(chaincodeInvocationSpec, util.GenerateUUID())
	if err != nil {
		errstr := fmt.Sprintf("Sign error: %v", err)
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: errstr})
		logger.Error(errstr)
	}

	resp, err := processTransaction(transaction)
	if err != nil {
		errstr := fmt.Sprintf("Sign error: %v", err)
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: errstr})
		logger.Error(errstr)

		return
	}
	if resp.Status != 200 {
		errstr := fmt.Sprintf("Sign error: %v", err)
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: errstr})
		logger.Error(errstr)

		return
	}

	rw.WriteHeader(http.StatusOK)
	encoder.Encode(restResult{OK: fmt.Sprintf("%s", signaturestr)})
	logger.Infof("Signature: '%s'.\n", signaturestr)

	return
}

// verify confirms the enrollmentID and secret password of the client with the
// CA and stores the enrollment certificate and key in the Devops server.
func (s *NotarizationAPP) verify(rw web.ResponseWriter, req *web.Request) {
	encoder := json.NewEncoder(rw)

	// Decode the incoming JSON payload
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: err.Error()})
		logger.Errorf("Error: %s", err)

		return
	}

	var verifyRequest verifyRequest
	err = json.Unmarshal(body, &verifyRequest)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: err.Error()})
		logger.Errorf("Error: %s", err)

		return
	}

	// Check that the enrollId and Signer are not left blank.
	if (verifyRequest.EnrollID == "") || (verifyRequest.Signer == "") {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "Signer may not be blank."})
		logger.Error("Error: Signer may not be blank.")

		return
	}

	// check the hash
	fileContent, err := base64.StdEncoding.DecodeString(verifyRequest.FileContent)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "fileContent may not be blank."})
		logger.Error("Error: fileContent may not be blank.")

		return
	}
	md5sum := md5.Sum(fileContent)
	fileHash := fmt.Sprintf("%02x", md5sum)
	if fileHash != strings.ToLower(verifyRequest.FileHash) {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "fileHash not match."})
		logger.Error("Error: fileHash not match.")

		return
	}

	args := []string{
		"verify",
		verifyRequest.Signer,
		verifyRequest.FileContent,
		verifyRequest.FileHash,
		verifyRequest.Signature}

	chaincodeInput := &pb.ChaincodeInput{
		Args: util.ToChaincodeArgs(args...),
	}

	spec := &pb.ChaincodeSpec{
		Type:                 1,
		ChaincodeID:          &pb.ChaincodeID{Name: chaincodeName},
		CtorMsg:              chaincodeInput,
		ConfidentialityLevel: confidentialityLevel,
	}

	chaincodeInvocationSpec := &pb.ChaincodeInvocationSpec{ChaincodeSpec: spec}

	// Get client
	client, err := initCryptoClient(verifyRequest.EnrollID, "")
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: fmt.Sprintf("Login error: %v", err)})
		logger.Errorf("Login error: %v", err)

		return
	}

	// Get the Transaction cert
	txCertHandler, err := client.GetTCertificateHandlerNext()
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "Verify error."})
		logger.Error("Error: Verify error.")

		return
	}
	txHandler, err := txCertHandler.GetTransactionHandler()
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "Verify error."})
		logger.Error("Error: Verify error.")

		return
	}

	// Now create the Transactions message and send to Peer.
	transaction, err := txHandler.NewChaincodeQuery(chaincodeInvocationSpec, util.GenerateUUID())
	if err != nil {
		errstr := fmt.Sprintf("Verify error: %v", err)
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: errstr})
		logger.Error(errstr)
	}

	resp, err := processTransaction(transaction)
	if err != nil {
		errstr := fmt.Sprintf("Verify error: %v", err)
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: errstr})
		logger.Error(errstr)

		return
	}
	if resp.Status != 200 {
		errstr := fmt.Sprintf("Verify error: %v", err)
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: errstr})
		logger.Error(errstr)

		return
	}

	var res []byte
	if confidentialityOn {
		// Decrypt result
		res, err = client.DecryptQueryResult(transaction, resp.Msg)
		if err != nil {
			logger.Errorf("Failed decrypting result [%s]", err)
			return
		}
	} else {
		res = resp.Msg
	}

	logger.Infof("Signature verify result: %v", string(res))
	if string(res) == verifyRequest.Signature {
		rw.WriteHeader(http.StatusOK)
		encoder.Encode(restResult{OK: fmt.Sprintf("Signature verified.")})
		logger.Infof("Signature verified.\n")
	} else {
		rw.WriteHeader(http.StatusOK)
		encoder.Encode(restResult{OK: fmt.Sprintf("Invalid signature.")})
		logger.Infof("Invalid signature.\n")
	}

	return
}

// getSignatures get signatures
func (s *NotarizationAPP) getSignatures(rw web.ResponseWriter, req *web.Request) {
	encoder := json.NewEncoder(rw)

	// Decode the incoming JSON payload
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: err.Error()})
		logger.Errorf("Error: %s", err)

		return
	}

	var signatureRequest signatureRequest
	err = json.Unmarshal(body, &signatureRequest)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: err.Error()})
		logger.Errorf("Error: %s", err)

		return
	}
	logger.Infof("signatureRequest: %v", signatureRequest)

	// Check that the enrollId and enrollSecret are not left blank.
	if (signatureRequest.EnrollID == "") || (signatureRequest.EnrollToken == "") {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "enrollId and enrollSecret may not be blank."})
		logger.Error("Error: enrollId and enrollSecret may not be blank.")

		return
	}

	args := []string{
		"getSignatures",
		signatureRequest.EnrollID}

	chaincodeInput := &pb.ChaincodeInput{
		Args: util.ToChaincodeArgs(args...),
	}

	spec := &pb.ChaincodeSpec{
		Type:                 1,
		ChaincodeID:          &pb.ChaincodeID{Name: chaincodeName},
		CtorMsg:              chaincodeInput,
		ConfidentialityLevel: confidentialityLevel,
	}

	chaincodeInvocationSpec := &pb.ChaincodeInvocationSpec{ChaincodeSpec: spec}

	// Get client
	client, err := initCryptoClient(signatureRequest.EnrollID, "")
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: fmt.Sprintf("Login error: %v", err)})
		logger.Errorf("Login error: %v", err)

		return
	}

	// Get the Transaction cert
	txCertHandler, err := client.GetTCertificateHandlerNext()
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "getSignatures error."})
		logger.Error("Error: getSignatures error.")

		return
	}
	txHandler, err := txCertHandler.GetTransactionHandler()
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "getSignatures error."})
		logger.Error("Error: getSignatures error.")

		return
	}

	// Now create the Transactions message and send to Peer.
	transaction, err := txHandler.NewChaincodeQuery(chaincodeInvocationSpec, util.GenerateUUID())
	if err != nil {
		errstr := fmt.Sprintf("getSignatures error: %v", err)
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: errstr})
		logger.Error(errstr)
	}

	resp, err := processTransaction(transaction)
	if err != nil {
		errstr := fmt.Sprintf("getSignatures error: %v", err)
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: errstr})
		logger.Error(errstr)

		return
	}
	if resp.Status != 200 {
		errstr := fmt.Sprintf("getSignatures error: %v", err)
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: errstr})
		logger.Error(errstr)

		return
	}

	var signatureResponse signatureResponse
	signatureResponse.OK = fmt.Sprintf("all signatures signed by %v", signatureRequest.EnrollID)

	var res []byte
	if confidentialityOn {
		// Decrypt result
		res, err = client.DecryptQueryResult(transaction, resp.Msg)
		if err != nil {
			logger.Errorf("Failed decrypting result [%s]", err)
			return
		}
	} else {
		res = resp.Msg
	}

	err = json.Unmarshal(res, &signatureResponse.Signatures)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: err.Error()})
		logger.Errorf("chaincode Error: %s", err)

		return
	}

	rw.WriteHeader(http.StatusOK)
	encoder.Encode(signatureResponse)
	logger.Infof("Get all signatures: %v.\n", signatureRequest.EnrollID)
}

// --------------- common function --------------
func deployChaincode(string) error {
	// Get chaincode path
	chaincodePath := os.Getenv("CORE_APP_NOTARIZATION_CHAINCODEPATH")
	if chaincodePath == "" {
		chaincodePath = viper.GetString("app.notarization.chaincodePath")
		if chaincodePath == "" {
			chaincodePath = "github.com/wutongtree/notarization/chaincode"
		}
	}

	// Get deployer
	deployerID := os.Getenv("CORE_APP_NOTARIZATION_DEPLOYER")
	if deployerID == "" {
		deployerID = viper.GetString("app.notarization.deployerID")
		if deployerID == "" {
			deployerID = "lukas"
		}
	}

	deployerSecret := os.Getenv("A_APP_NOTARIZATION_DEPLOYERSECRET")
	if deployerSecret == "" {
		deployerSecret = viper.GetString("app.notarization.deployerSecret")
		if deployerSecret == "" {
			deployerSecret = "NPKYL39uKbkj"
		}
	}

	// init deployer
	deployerClient, err := initCryptoClient(deployerID, deployerSecret)
	if err != nil {
		logger.Debugf("Failed deploying [%s]", err)
		return err
	}

	// Prepare the spec. The metadata includes the identity of the administrator
	spec := &pb.ChaincodeSpec{
		Type:                 1,
		ChaincodeID:          &pb.ChaincodeID{Path: chaincodePath},
		CtorMsg:              &pb.ChaincodeInput{Args: util.ToChaincodeArgs("init")},
		ConfidentialityLevel: confidentialityLevel,
	}

	// First build the deployment spec
	cds, err := getChaincodeBytes(spec)
	if err != nil {
		return fmt.Errorf("Error getting deployment spec: %s ", err)
	}

	logger.Infof("deployChaincode: %v", cds.ChaincodeSpec)

	// Now create the Transactions message and send to Peer.
	transaction, err := deployerClient.NewChaincodeDeployTransaction(cds, cds.ChaincodeSpec.ChaincodeID.Name)
	if err != nil {
		return fmt.Errorf("Error deploying chaincode: %s ", err)
	}

	resp, err := processTransaction(transaction)

	logger.Debugf("resp [%s]", resp.String())

	chaincodeName = cds.ChaincodeSpec.ChaincodeID.Name
	logger.Debugf("ChaincodeName [%s]", chaincodeName)

	return nil
}

// StartNotarizationServer initializes the REST service and adds the required
// middleware and routes.
func startNotarizationServer() {
	// Initialize the REST service object
	tlsEnabled := viper.GetBool("app.tls.enabled")

	logger.Infof("Initializing the REST service on %s, TLS is %s.", viper.GetString("app.address"), (map[bool]string{true: "enabled", false: "disabled"})[tlsEnabled])

	router := buildNotarizationRouter()

	// Start server
	if tlsEnabled {
		err := http.ListenAndServeTLS(viper.GetString("app.address"), viper.GetString("app.tls.cert.file"), viper.GetString("app.tls.key.file"), router)
		if err != nil {
			logger.Errorf("ListenAndServeTLS: %s", err)
		}
	} else {
		err := http.ListenAndServe(viper.GetString("app.address"), router)
		if err != nil {
			logger.Errorf("ListenAndServe: %s", err)
		}
	}
}

// start serve
func serve(args []string) error {
	// Create and register the REST service if configured
	startNotarizationServer()

	logger.Infof("Starting app...")

	return nil
}
