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
	"time"

	"github.com/spf13/viper"
)

func getHTTPURL(resource string) string {
	var restServer = os.Getenv("CORE_REST_ADDRESS")
	if restServer == "" {
		restServer = viper.GetString("rest.address")
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
