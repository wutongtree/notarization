package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/net/context"

	"github.com/hyperledger/fabric/core/chaincode"
	"github.com/hyperledger/fabric/core/chaincode/platforms"
	"github.com/hyperledger/fabric/core/config"
	"github.com/hyperledger/fabric/core/container"
	"github.com/hyperledger/fabric/core/crypto"
	"github.com/hyperledger/fabric/core/peer"
	pb "github.com/hyperledger/fabric/protos"
	"github.com/spf13/viper"
)

func initNVP() (err error) {
	config.SetupTestConfig(".")
	viper.Set("ledger.blockchain.deploy-system-chaincode", "false")
	viper.Set("peer.validator.validity-period.verification", "false")

	peerClientConn, err = peer.NewPeerClientConnection()
	if err != nil {
		fmt.Printf("error connection to server at host:port = %s\n", viper.GetString("peer.address"))
		return
	}
	serverClient = pb.NewPeerClient(peerClientConn)

	return
}

func initCryptoClient(enrollID, enrollPWD string) (crypto.Client, error) {
	// RegisterClient
	if enrollPWD != "" {
		if err := crypto.RegisterClient(enrollID, nil, enrollID, enrollPWD); err != nil {
			return nil, err
		}
	}

	client, err := crypto.InitClient(enrollID, nil)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func processTransaction(tx *pb.Transaction) (*pb.Response, error) {
	return serverClient.ProcessTransaction(context.Background(), tx)
}

func confidentiality(enabled bool) {
	confidentialityOn = enabled

	if confidentialityOn {
		confidentialityLevel = pb.ConfidentialityLevel_CONFIDENTIAL
	} else {
		confidentialityLevel = pb.ConfidentialityLevel_PUBLIC
	}
}

func getChaincodeBytes(spec *pb.ChaincodeSpec) (*pb.ChaincodeDeploymentSpec, error) {
	mode := viper.GetString("chaincode.mode")
	var codePackageBytes []byte
	if mode != chaincode.DevModeUserRunsChaincode {
		logger.Debugf("Received build request for chaincode spec: %v", spec)
		var err error
		if err = checkSpec(spec); err != nil {
			return nil, err
		}

		codePackageBytes, err = container.GetChaincodePackageBytes(spec)
		if err != nil {
			err = fmt.Errorf("Error getting chaincode package bytes: %s", err)
			logger.Errorf("%s", err)
			return nil, err
		}
	}
	chaincodeDeploymentSpec := &pb.ChaincodeDeploymentSpec{ChaincodeSpec: spec, CodePackage: codePackageBytes}
	return chaincodeDeploymentSpec, nil
}

func checkSpec(spec *pb.ChaincodeSpec) error {
	// Don't allow nil value
	if spec == nil {
		return errors.New("Expected chaincode specification, nil received")
	}

	platform, err := platforms.Find(spec.Type)
	if err != nil {
		return fmt.Errorf("Failed to determine platform type: %s", err)
	}

	return platform.ValidateSpec(spec)
}

func getHTTPURL(resource string) string {
	var restServer = os.Getenv("CORE_REST_ADDRESS")
	if restServer == "" {
		restServer = viper.GetString("rest.address")
	}

	server := strings.Split(restServer, ":")
	if len(server) < 2 {
		return fmt.Sprintf("http://%v/%v", restServer, resource)
	}

	if server[1] == "443" {
		return fmt.Sprintf("https://%v/%v", server[0], resource)
	}

	return fmt.Sprintf("http://%v/%v", restServer, resource)
}

func serializeObject(obj interface{}) (string, error) {
	r, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}

	result := string(r)
	if result == "null" {
		return "", errors.New("null object")
	}

	return result, nil
}

func deserializeObject(str string) (interface{}, error) {
	var obj interface{}

	err := json.Unmarshal([]byte(str), &obj)
	if err != nil {
		return nil, err
	}

	if obj == nil {
		return nil, errors.New("null object")
	}

	return obj, nil
}

func performHTTPGet(url string) ([]byte, error) {
	client := &http.Client{
		Transport: &http.Transport{
			Dial: func(netw, addr string) (net.Conn, error) {
				conn, err := net.DialTimeout(netw, addr, time.Second*3)
				if err != nil {
					return nil, err
				}
				conn.SetDeadline(time.Now().Add(time.Second * 60))
				return conn, nil
			},
			ResponseHeaderTimeout: time.Second * 60,
		},
	}
	rsp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer rsp.Body.Close()
	body, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

func performHTTPPost(url string, b []byte) ([]byte, error) {
	client := &http.Client{
		Transport: &http.Transport{
			Dial: func(netw, addr string) (net.Conn, error) {
				conn, err := net.DialTimeout(netw, addr, time.Second*3)
				if err != nil {
					return nil, err
				}
				conn.SetDeadline(time.Now().Add(time.Second * 60))
				return conn, nil
			},
			ResponseHeaderTimeout: time.Second * 60,
		},
	}

	body := bytes.NewBuffer([]byte(b))
	res, err := client.Post(url, "application/json;charset=utf-8", body)
	if err != nil {

		return nil, err
	}
	result, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {

		return nil, err
	}

	return result, nil
}

func performHTTPDelete(url string) []byte {
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return nil
	}
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	body, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return nil
	}

	return body
}
