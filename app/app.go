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
	"net/url"

	"github.com/spf13/cobra"

	"github.com/gocraft/web"
	"github.com/hyperledger/fabric/core/comm"
	"github.com/hyperledger/fabric/core/crypto"
	"github.com/hyperledger/fabric/core/util"
	pb "github.com/hyperledger/fabric/protos"
	"github.com/spf13/viper"
)

// var

var (
	stopPidFile   string
	versionFlag   bool
	chaincodeName string
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
	EnrollToken string `protobuf:"bytes,2,opt,name=enrollToken" json:"enrollToken,omitempty"`
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

	// Retrieve the REST data
	url := getHTTPURL("registrar")
	var loginSpec pb.Secret
	loginSpec.EnrollId = loginRequest.EnrollID
	loginSpec.EnrollSecret = loginRequest.EnrollSecret
	reqBody, err := json.Marshal(loginSpec)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "get request error."})
		logger.Errorf("Error: get request error: %v", err)

		return
	}
	logger.Debugf("registrar request: %v - %v", url, string(reqBody))
	response, err := performHTTPPost(url, reqBody)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "get data error."})
		logger.Error("Error: get data error.")

		return
	}
	logger.Debugf("registrar response: %v - %v", url, string(response))

	var result restResult
	err = json.Unmarshal(response, &result)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "Unmarshal error"})
		logger.Error("Error: Unmarshal error.")

		return
	}
	logger.Debugf("registrar: %v - %v", loginRequest.EnrollID, result.OK)

	// Store client security context into a file
	localStore := getRESTFilePath()

	logger.Infof("Storing login token for user '%s'.\n", loginRequest.EnrollID)
	err = ioutil.WriteFile(localStore+"loginToken_"+loginRequest.EnrollID, []byte(loginRequest.EnrollID), 0755)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		encoder.Encode(restResult{Error: fmt.Sprintf("Fatal error -- %s", err)})
		panic(fmt.Errorf("Fatal error when storing client login token: %s\n", err))

		return
	}

	// Register local
	err = crypto.RegisterClient(loginRequest.EnrollID, nil, loginRequest.EnrollID, loginRequest.EnrollSecret)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		encoder.Encode(restResult{Error: fmt.Sprintf("Fatal error -- %s", err)})
		panic(fmt.Errorf("Fatal error when storing client login token: %s\n", err))

		return
	}

	rw.WriteHeader(http.StatusOK)
	encoder.Encode(restResult{OK: fmt.Sprintf("Login successful for user '%s'.", loginRequest.EnrollID)})
	logger.Infof("Login successful for user '%s'.\n", loginRequest.EnrollID)

	// deploy the chaincode
	if chaincodeName == "" {
		deployChaincode(loginRequest.EnrollID)
	}

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
	logger.Infof("signRequest: %v", signRequest)

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

	// retrieve the local file
	localStore := getRESTFilePath()
	token, err := ioutil.ReadFile(localStore + "loginToken_" + signRequest.EnrollID)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		encoder.Encode(restResult{Error: fmt.Sprintf("Fatal error -- %s", err)})
		panic(fmt.Errorf("Fatal error when storing client login token: %s\n", err))
	}
	logger.Debugf("token: %v - %v", signRequest.EnrollToken, string(token))

	// Retrieve the REST data
	urlstr := getHTTPURL("registrar/" + signRequest.EnrollID + "/ecert")
	logger.Infof("url request: %v", urlstr)
	response, err := performHTTPGet(urlstr)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "get data error."})
		logger.Error("Error: get data error.")

		return
	}
	logger.Debugf("url response: %v - %v", urlstr, string(response))

	var result certsResult
	err = json.Unmarshal(response, &result)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "Unmarshal error"})
		logger.Error("Error: Unmarshal error.")
		return
	}
	logger.Debugf("registrar: %v - %v", signRequest.EnrollID, result.OK)

	if len(result.OK) <= 0 {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "Get ecert error."})
		logger.Errorf("Get ecert error.")

		return
	}

	certString, err := url.QueryUnescape(result.OK)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "QueryUnescape error."})
		logger.Error("Error: QueryUnescape error.")

		return
	}

	// Init a client to sign
	crypto.Init()

	client, err := crypto.InitClient(signRequest.EnrollID, nil)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "InitClient error."})
		logger.Error("Error: InitClient error.")
		return
	}
	handler, err := client.GetEnrollmentCertificateHandler()
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "GetEnrollmentCertificateHandler error."})
		logger.Error("Error: GetEnrollmentCertificateHandler error.")

		return
	}

	signature, err := handler.Sign(fileContent)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "Sign error."})
		logger.Error("Error: Sign error.")

		return
	}

	signaturestr := base64.StdEncoding.EncodeToString(signature)

	// TODO: no need to verify
	// Verify
	err = handler.Verify(signature, fileContent)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "Verify error."})
		logger.Error("Error: Verify error.")

		return
	}

	filePath := localStore + "/" + "files"

	location, _ := time.LoadLocation("Asia/Chongqing")
	timestr := time.Now().In(location).String()

	// invoke the chaincode
	var signChaincode chaincodeRequest
	var params pb.ChaincodeSpec
	args := []string{
		"sign",
		signRequest.EnrollID,
		certString,
		signRequest.FileName,
		filePath,
		signRequest.FileContent,
		signRequest.FileHash,
		signaturestr,
		timestr}

	params.Type = pb.ChaincodeSpec_GOLANG
	params.ChaincodeID = &pb.ChaincodeID{
		Name: chaincodeName,
	}
	params.CtorMsg = &pb.ChaincodeInput{Args: util.ToChaincodeArgs(args...)}
	params.SecureContext = signRequest.EnrollID

	signChaincode.Jsonrpc = "2.0"
	signChaincode.Method = "invoke"
	signChaincode.Params = params
	signChaincode.ID = timestr

	reqBody, err := json.Marshal(signChaincode)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "Marshal error."})
		logger.Errorf("Error: Marshal error: %v", err)

		return
	}

	urlstr = getHTTPURL("chaincode")
	logger.Debugf("url request: %v, %v", urlstr, string(reqBody))
	response, err = performHTTPPost(urlstr, reqBody)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "get data error."})
		logger.Error("Error: get data error.")

		return
	}
	logger.Debugf("url response: %v - %v", urlstr, string(response))

	// parse result
	var chaincodeResponse chaincodeResponse
	err = json.Unmarshal(response, &chaincodeResponse)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: err.Error()})
		logger.Errorf("Verify Error: %s", err)

		return
	}

	if chaincodeResponse.Result.Status != "OK" {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "Sign file error."})
		logger.Errorf("Sign file error.")

		return
	}

	// return
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
	logger.Infof("verifyRequest: %v", verifyRequest)

	// Check that the enrollId and enrollSecret are not left blank.
	if (verifyRequest.EnrollID == "") || (verifyRequest.EnrollToken == "") {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "enrollId and enrollSecret may not be blank."})
		logger.Error("Error: enrollId and enrollSecret may not be blank.")

		return
	}

	// check the hash
	fileContent, err := base64.StdEncoding.DecodeString(verifyRequest.FileContent)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "enrollId and enrollSecret may not be blank."})
		logger.Error("Error: enrollId and enrollSecret may not be blank.")

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

	// invoke the chaincode
	location, _ := time.LoadLocation("Asia/Chongqing")
	timestr := time.Now().In(location).String()

	var verifyChaincode chaincodeRequest
	var params pb.ChaincodeSpec
	args := []string{
		"verify",
		verifyRequest.EnrollID,
		verifyRequest.FileContent,
		verifyRequest.FileHash,
		verifyRequest.Signature}

	params.Type = pb.ChaincodeSpec_GOLANG
	params.ChaincodeID = &pb.ChaincodeID{
		Name: chaincodeName,
	}
	params.CtorMsg = &pb.ChaincodeInput{Args: util.ToChaincodeArgs(args...)}
	params.SecureContext = verifyRequest.EnrollID

	verifyChaincode.Jsonrpc = "2.0"
	verifyChaincode.Method = "query"
	verifyChaincode.Params = params
	verifyChaincode.ID = timestr

	reqBody, err := json.Marshal(verifyChaincode)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "Marshal error."})
		logger.Errorf("Error: Marshal error: %v", err)

		return
	}

	urlstr := getHTTPURL("chaincode")
	logger.Debugf("url request: %v, %v", urlstr, string(reqBody))
	response, err := performHTTPPost(urlstr, reqBody)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "get data error."})
		logger.Error("Error: get data error.")

		return
	}
	logger.Debugf("url response: %v - %v", urlstr, string(response))

	// parse result
	var chaincodeResponse chaincodeResponse
	err = json.Unmarshal(response, &chaincodeResponse)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: err.Error()})
		logger.Errorf("Verify Error: %s", err)

		return
	}

	if chaincodeResponse.Result.Status != "OK" {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "Verify signature error."})
		logger.Errorf("Verify signature error.")

		return
	}

	if chaincodeResponse.Result.Message == verifyRequest.Signature {
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

	// invoke the chaincode
	location, _ := time.LoadLocation("Asia/Chongqing")
	timestr := time.Now().In(location).String()

	var signatureChaincode chaincodeRequest
	var params pb.ChaincodeSpec
	args := []string{
		"getSignatures",
		signatureRequest.EnrollID}

	params.Type = pb.ChaincodeSpec_GOLANG
	params.ChaincodeID = &pb.ChaincodeID{
		Name: chaincodeName,
	}
	params.CtorMsg = &pb.ChaincodeInput{Args: util.ToChaincodeArgs(args...)}
	params.SecureContext = signatureRequest.EnrollID

	signatureChaincode.Jsonrpc = "2.0"
	signatureChaincode.Method = "query"
	signatureChaincode.Params = params
	signatureChaincode.ID = timestr

	reqBody, err := json.Marshal(signatureChaincode)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "Marshal error."})
		logger.Errorf("Error: Marshal error: %v", err)

		return
	}

	urlstr := getHTTPURL("chaincode")
	logger.Infof("url request: %v, %v", urlstr, string(reqBody))
	response, err := performHTTPPost(urlstr, reqBody)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "get data error."})
		logger.Error("Error: get data error.")

		return
	}
	logger.Infof("url response: %v - %v", urlstr, string(response))

	// parse result
	var chaincodeResponse chaincodeResponse
	err = json.Unmarshal(response, &chaincodeResponse)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: err.Error()})
		logger.Errorf("chaincode Error: %s", err)

		return
	}

	if chaincodeResponse.Result.Status != "OK" {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: "get signature none"})
		logger.Errorf("get signature none")

		return
	}

	var signatureResponse signatureResponse
	signatureResponse.OK = fmt.Sprintf("all signatures signed by %v", signatureRequest.EnrollID)

	signatures := []byte(chaincodeResponse.Result.Message)
	err = json.Unmarshal(signatures, &signatureResponse.Signatures)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(restResult{Error: err.Error()})
		logger.Errorf("chaincode Error: %s", err)

		return
	}

	rw.WriteHeader(http.StatusOK)
	encoder.Encode(signatureResponse)
	logger.Infof("Get all signatures: %v.\n", signatureRequest.EnrollID)

	return
}

// --------------- common func --------------

func deployChaincode(secureContext string) {
	var chaincodePath = os.Getenv("APP_APP_NOTARIZATION_CHAINCODEPATH")
	if chaincodePath == "" {
		chaincodePath = viper.GetString("app.notarization.chaincodePath")
		if chaincodePath == "" {
			chaincodePath = "github.com/wutongtree/notarization/chaincode"
		}
	}

	if secureContext == "" {
		deployer := os.Getenv("APP_APP_NOTARIZATION_DEPLOYER")
		if deployer == "" {
			deployer = viper.GetString("app.notarization.deployer")
			if deployer == "" {
				deployer = "lukas"
			}
		}

		deployerSecret := os.Getenv("APP_APP_NOTARIZATION_DEPLOYERSECRET")
		if deployerSecret == "" {
			deployerSecret = viper.GetString("app.notarization.deployerSecret")
			if deployerSecret == "" {
				deployerSecret = "NPKYL39uKbkj"
			}
		}

		// Retrieve the REST data
		url := getHTTPURL("registrar")
		var loginSpec pb.Secret
		loginSpec.EnrollId = deployer
		loginSpec.EnrollSecret = deployerSecret
		reqBody, err := json.Marshal(loginSpec)
		if err != nil {
			logger.Errorf("Error: get request error: %v", err)

			return
		}
		logger.Debugf("registrar request: %v - %v", url, string(reqBody))
		response, err := performHTTPPost(url, reqBody)
		if err != nil {
			logger.Error("Error: get data error.")

			return
		}
		logger.Debugf("registrar response: %v - %v", url, string(response))

		var result restResult
		err = json.Unmarshal(response, &result)
		if err != nil {
			logger.Error("Error: Unmarshal error.")

			return
		}
		logger.Debugf("registrar: %v - %v", deployer, result.OK)

		// Store client security context into a file
		localStore := getRESTFilePath()

		logger.Infof("Storing login token for user '%s'.\n", deployer)
		err = ioutil.WriteFile(localStore+"loginToken_"+deployer, []byte(deployer), 0755)
		if err != nil {
			panic(fmt.Errorf("Fatal error when storing client login token: %s\n", err))

			return
		}

		secureContext = deployer
	}

	// deploy chaincode
	location, _ := time.LoadLocation("Asia/Chongqing")
	timestr := time.Now().In(location).String()

	var deployhaincode chaincodeRequest
	var params pb.ChaincodeSpec
	args := []string{"init"}

	params.Type = pb.ChaincodeSpec_GOLANG
	params.ChaincodeID = &pb.ChaincodeID{
		Path: chaincodePath,
	}
	params.CtorMsg = &pb.ChaincodeInput{Args: util.ToChaincodeArgs(args...)}
	params.SecureContext = secureContext

	deployhaincode.Jsonrpc = "2.0"
	deployhaincode.Method = "deploy"
	deployhaincode.Params = params
	deployhaincode.ID = timestr

	reqBody, err := json.Marshal(deployhaincode)
	if err != nil {
		logger.Errorf("Error: Marshal error: %v", err)

		return
	}

	urlstr := getHTTPURL("chaincode")
	logger.Infof("url request: %v, %v", urlstr, string(reqBody))
	response, err := performHTTPPost(urlstr, reqBody)
	if err != nil {
		logger.Error("Error: get data error.")

		return
	}
	logger.Infof("url response: %v - %v", urlstr, string(response))

	// parse result
	var chaincodeResponse chaincodeResponse
	err = json.Unmarshal(response, &chaincodeResponse)
	if err != nil {
		logger.Errorf("chaincode Error: %v", err)

		return
	}

	// cache the chaincodeName
	if chaincodeResponse.Result.Status != "OK" {
		logger.Errorf("chaincode Status Error: %v", chaincodeResponse.Result.Status)

		return
	}
	chaincodeName = chaincodeResponse.Result.Message
	logger.Infof("deploy chaincode: %v", chaincodeName)
}

// getRESTFilePath is a helper function to retrieve the local storage directory
// of client login tokens.
func getRESTFilePath() string {
	localStore := viper.GetString("peer.fileSystemPath")
	if !strings.HasSuffix(localStore, "/") {
		localStore = localStore + "/"
	}
	localStore = localStore + "client/"
	return localStore
}

// StartNotarizationServer initializes the REST service and adds the required
// middleware and routes.
func startNotarizationServer() {
	// Initialize the REST service object
	logger.Infof("Initializing the REST service on %s, TLS is %s.", viper.GetString("app.address"), (map[bool]string{true: "enabled", false: "disabled"})[comm.TLSEnabled()])

	router := buildNotarizationRouter()

	// Start server
	if comm.TLSEnabled() {
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
	// Deploy the chaincode
	deployChaincode("")

	// Create and register the REST service if configured
	startNotarizationServer()

	logger.Infof("Starting app...")

	return nil
}
