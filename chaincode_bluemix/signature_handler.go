package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hyperledger/fabric/core/chaincode/shim"
)

// consts associated with chaincode table
const (
	tableColumn         = "Notarization"
	columnAccountID     = "AccountID"
	columnCertificate   = "Certificate"
	columnFileName      = "FileName"
	columnFileHash      = "FileHash"
	columnFileSignature = "FileSignature"
	columnTimestamp     = "Timestamp"
)

// signatureResponse
type signatureEntity struct {
	FileHash      string `json:"fileHash,omitempty"`
	FileName      string `json:"fileName,omitempty"`
	FileSignature string `json:"fileSignature,omitempty"`
	Timestamp     string `json:"timestamp,omitempty"`
}

//SignatureHandler provides APIs used to perform operations on CC's KV store
type signatureHandler struct {
}

// NewSignatureHandler create a new reference to CertHandler
func NewSignatureHandler() *signatureHandler {
	return &signatureHandler{}
}

// createTable initiates a new asset signature table in the chaincode state
// stub: chaincodestub
func (t *signatureHandler) createTable(stub *shim.ChaincodeStub) error {

	// Create asset signature table
	return stub.CreateTable(tableColumn, []*shim.ColumnDefinition{
		&shim.ColumnDefinition{Name: columnAccountID, Type: shim.ColumnDefinition_STRING, Key: true},
		&shim.ColumnDefinition{Name: columnFileSignature, Type: shim.ColumnDefinition_BYTES, Key: true},
		&shim.ColumnDefinition{Name: columnFileHash, Type: shim.ColumnDefinition_STRING, Key: true},
		&shim.ColumnDefinition{Name: columnCertificate, Type: shim.ColumnDefinition_STRING, Key: false},
		&shim.ColumnDefinition{Name: columnFileName, Type: shim.ColumnDefinition_STRING, Key: false},
		&shim.ColumnDefinition{Name: columnTimestamp, Type: shim.ColumnDefinition_STRING, Key: false},
	})
}

// submitSignature submit signature
// accountID: account ID to be allocated with requested amount
// certficate: pem format of certficate
// fileName: file name
// fileHash: file hash
// fileSignature: file signature
// timestamp: timestamp
func (t *signatureHandler) submitSignature(stub *shim.ChaincodeStub,
	accountID string,
	certficate string,
	fileName string,
	fileHash string,
	fileSignature []byte,
	timestamp string) error {

	logger.Debugf("insert accountID=%v certficate=%v fileName=%v fileHash=%v fileSignature=%v timestamp=%v", accountID, certficate, fileName, fileHash, fileSignature, timestamp)

	//insert a new row for this account ID that includes contact information and balance
	ok, err := stub.InsertRow(tableColumn, shim.Row{
		Columns: []*shim.Column{
			&shim.Column{Value: &shim.Column_String_{String_: accountID}},
			&shim.Column{Value: &shim.Column_Bytes{Bytes: fileSignature}},
			&shim.Column{Value: &shim.Column_String_{String_: fileHash}},
			&shim.Column{Value: &shim.Column_String_{String_: certficate}},
			&shim.Column{Value: &shim.Column_String_{String_: fileName}},
			&shim.Column{Value: &shim.Column_String_{String_: timestamp}}},
	})

	// you can only assign balances to new account IDs
	if !ok && err == nil {
		logger.Errorf("submitSignature: system error %v", err)
		return errors.New("Fiel was already signed.")
	}

	return nil
}

// queryTable returns the record row matching a correponding account ID and fileHash on the chaincode state table
// stub: chaincodestub
// accountID: account ID
// fileHash: file hash
// fileSignature:  file signature
func (t *signatureHandler) queryTable(stub *shim.ChaincodeStub, accountID string, fileHash string, fileSignature []byte) (shim.Row, error) {

	var columns []shim.Column
	col1 := shim.Column{Value: &shim.Column_String_{String_: accountID}}
	col2 := shim.Column{Value: &shim.Column_Bytes{Bytes: fileSignature}}
	col3 := shim.Column{Value: &shim.Column_String_{String_: fileHash}}
	columns = append(columns, col1)
	columns = append(columns, col2)
	columns = append(columns, col3)

	return stub.GetRow(tableColumn, columns)
}

// queryTables returns the record row matching a correponding account ID and fileHash on the chaincode state table
// stub: chaincodestub
// accountID: account ID
func (t *signatureHandler) queryTables(stub *shim.ChaincodeStub, accountID string) (<-chan shim.Row, error) {

	var columns []shim.Column
	col1 := shim.Column{Value: &shim.Column_String_{String_: accountID}}
	columns = append(columns, col1)

	return stub.GetRows(tableColumn, columns)
}

// getCertificate queries the certficate information matching a correponding account ID and fileHash on the chaincode state table
// stub: chaincodestub
// accountID: account ID
// fileHash: file hash
// fileSignature:  file signature
func (t *signatureHandler) getCertificate(stub *shim.ChaincodeStub, accountID string, fileHash string, fileSignature []byte) (string, error) {
	row, err := t.queryTable(stub, accountID, fileHash, fileSignature)
	if err != nil {
		return "", err
	}

	if len(row.Columns) < 3 {
		logger.Errorf("getCertificate rows: %v", len(row.Columns))
		return "", nil
	}

	return row.Columns[3].GetString_(), nil
}

// getSignatures queries the certficate information matching a correponding account ID and fileHash on the chaincode state table
// stub: chaincodestub
// accountID: account ID
func (t *signatureHandler) getSignatures(stub *shim.ChaincodeStub, accountID string) ([]byte, error) {
	rowChannel, err := t.queryTables(stub, accountID)
	if err != nil {
		return nil, err
	}

	var rows []shim.Row
	for {
		select {
		case row, ok := <-rowChannel:
			if !ok {
				rowChannel = nil
			} else {
				rows = append(rows, row)
			}
		}
		if rowChannel == nil {
			break
		}
	}

	var signatures []signatureEntity
	for _, row := range rows {
		var signatureEntity signatureEntity
		signatureEntity.FileSignature = base64.StdEncoding.EncodeToString(row.Columns[1].GetBytes())
		signatureEntity.FileHash = row.Columns[2].GetString_()
		signatureEntity.FileName = row.Columns[4].GetString_()
		signatureEntity.Timestamp = row.Columns[5].GetString_()

		signatures = append(signatures, signatureEntity)
	}

	jsonRows, err := json.Marshal(signatures)
	if err != nil {
		return nil, fmt.Errorf("getSignatures failed: %s", err)
	}

	return jsonRows, nil
}
