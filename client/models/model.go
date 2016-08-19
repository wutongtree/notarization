package models

import (
	"encoding/json"

	"github.com/astaxie/beego"
)

var (
	appServer string
)

func init() {
	appServer = beego.AppConfig.String("app_server")
}

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

// SignatureResponse response of signatures
type SignatureResponse struct {
	OK         string            `json:"OK,omitempty"`
	Error      string            `json:"Error,omitempty"`
	Signatures []signatureEntity `json:"signatures,omitempty"`
}

// Login login
// enrollID: enrollID
// enrollSecret: enrollSecret
func Login(enrollID, enrollSecret string) bool {
	var loginRequest loginRequest
	loginRequest.EnrollID = enrollID
	loginRequest.EnrollSecret = enrollSecret

	reqBody, err := json.Marshal(loginRequest)
	if err != nil {
		return false
	}

	urlstr := getHTTPURL("login")
	response, err := performHTTPPost(urlstr, reqBody)
	if err != nil {
		return false
	}

	var result restResult
	err = json.Unmarshal(response, &result)
	if err != nil {
		return false
	}

	if result.OK == "" {
		return false
	}

	return true
}

// GetSignatures get signatures
// enrollID: enrollID
// enrollToken: enrollToken
func GetSignatures(enrollID, enrollToken string) *SignatureResponse {
	var signatureRequest signatureRequest
	signatureRequest.EnrollID = enrollID
	signatureRequest.EnrollToken = enrollToken

	reqBody, err := json.Marshal(signatureRequest)
	if err != nil {
		return nil
	}

	urlstr := getHTTPURL("getSignatures")
	response, err := performHTTPPost(urlstr, reqBody)
	if err != nil {
		return nil
	}

	var result SignatureResponse
	err = json.Unmarshal(response, &result)
	if err != nil {
		return nil
	}

	if result.OK == "" {
		return nil
	}

	return &result
}

// Sign sign a file
// enrollID: enrollID
// enrollToken: enrollToken
// fileName: file name
// fileContent: base64 of file content
// fileHash: sha256 of file content
func Sign(enrollID, enrollToken, fileName, fileContent, fileHash string) string {
	var signRequest signRequest
	signRequest.EnrollID = enrollID
	signRequest.EnrollToken = enrollToken
	signRequest.FileName = fileName
	signRequest.FileContent = fileContent
	signRequest.FileHash = fileHash

	reqBody, err := json.Marshal(signRequest)
	if err != nil {
		return ""
	}

	urlstr := getHTTPURL("sign")
	response, err := performHTTPPost(urlstr, reqBody)
	if err != nil {
		return ""
	}

	var result restResult
	err = json.Unmarshal(response, &result)
	if err != nil {
		return ""
	}

	if result.OK == "" {
		return ""
	}

	return result.OK
}

// Verify verify a signature
// enrollID: enrollID
// enrollToken: enrollToken
// fileContent: base64 of file content
// fileHash: sha256 of file content
// signature: signature of file
func Verify(enrollID, enrollToken, fileContent, fileHash, signature string) bool {
	var verifyRequest verifyRequest
	verifyRequest.EnrollID = enrollID
	verifyRequest.EnrollToken = enrollToken
	verifyRequest.FileContent = fileContent
	verifyRequest.FileHash = fileHash
	verifyRequest.Signature = signature

	reqBody, err := json.Marshal(verifyRequest)
	if err != nil {
		return false
	}

	urlstr := getHTTPURL("verify")
	response, err := performHTTPPost(urlstr, reqBody)
	if err != nil {
		return false
	}

	var result restResult
	err = json.Unmarshal(response, &result)
	if err != nil {
		return false
	}

	if result.OK == "" {
		return false
	}

	return true
}
