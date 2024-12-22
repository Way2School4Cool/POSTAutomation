package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	//openssl pkcs12 -export -inkey mykey.pem -in mycert.pem -out output.p12 -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -export -macalg sha1

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go/aws"
	"golang.org/x/crypto/pkcs12"
)

var cfg Config

type Config struct {
	FolderPath      string `json:"folderPath"`
	APIEndpoint     string `json:"apiEndpoint"`
	ResponsesFile   string `json:"responsesFile"`
	PfxPath         string `json:"pfxPath"`
	PfxPassword     string `json:"pfxPassword"`
	AWSRegion       string `json:"awsRegion"`
	LogGroupName    string `json:"logGroupName"`
	AWSAccessKey    string `json:"awsAccessKey"`
	AWSSecretKey    string `json:"awsSecretKey"`
	AWSSessionToken string `json:"awsSessionToken"`
}

type PendingTransaction struct {
	FileName      string
	TransactionID string
	IsFollowup    bool
	ContractID    string
}

type QueueEnrollment struct {
	XMLName   xml.Name  `xml:"QueueEnrollment"`
	Contracts Contracts `xml:"contracts"`
}

type Contracts struct {
	Contract Contract `xml:"contract"`
}

type Contract struct {
	ContractID string `xml:"contractID"`
}

func loadConfig() Config {
	file, err := os.ReadFile("config.json")
	if err != nil {
		log.Fatalf("Failed to read config file: %v", err)
	}

	var config Config
	if err := json.Unmarshal(file, &config); err != nil {
		log.Fatalf("Failed to parse config file: %v", err)
	}

	return config
}

func main() {
	cfg = loadConfig()

	// Process CSV file to get batch groups
	batchGroups := loadBatchGroups(cfg.ResponsesFile)

	for _, batch := range batchGroups {
		processBatch(batch)
	}
}

func loadBatchGroups(csvPath string) [][]string {
	file, err := os.Open(csvPath)
	if err != nil {
		log.Fatalf("Failed to open CSV file: %v", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	// Make reader more flexible by not enforcing field count
	reader.FieldsPerRecord = -1
	// Skip header
	reader.Read()

	var batches [][]string
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("Error reading CSV: %v", err)
			continue
		}
		// Only process records that have at least one file
		if len(record) >= 2 { // At least batch ID and one file
			batches = append(batches, record)
		} else {
			log.Printf("Skipping invalid record: insufficient fields")
		}
	}
	return batches
}

func processBatch(batch []string) {
	// Ensure there's at least one file in the batch
	if len(batch) < 2 {
		log.Printf("Skipping batch: no files to process")
		return
	}

	files := batch[1:] // First element is batch ID, rest are files

	// Process first file normally
	firstFile := files[0]
	transaction := apiRequestHandler(firstFile, false, "")
	if transaction == nil {
		log.Printf("Failed to process primary file %s, skipping batch", firstFile)
		return
	}

	// Get ContractID from AWS and update if not set
	contractID, err := queryAWSData(context.Background(), cfg, transaction.TransactionID)
	if err != nil {
		log.Printf("Failed to get ContractID for primary file %s: %v", firstFile, err)
		return
	}

	// Process followup files
	for _, followupFile := range files[1:] {
		// Update XML content with ContractID before sending
		if err := updateXMLWithContractID(followupFile, contractID); err != nil {
			log.Printf("Failed to update file %s with ContractID: %v", followupFile, err)
			continue
		}

		transaction := apiRequestHandler(followupFile, true, contractID)
		if transaction == nil {
			log.Printf("Failed to process followup file %s", followupFile)
			continue
		}

		// Wait for AWS confirmation for each followup
		_, err := queryAWSData(context.Background(), cfg, transaction.TransactionID)
		if err != nil {
			log.Printf("Failed to confirm followup file %s: %v", followupFile, err)
		}
	}
}

func updateXMLWithContractID(filename string, contractID string) error {
	filePath := filepath.Join(cfg.FolderPath, filename)
	xmlData, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read XML file: %v", err)
	}

	decoder := xml.NewDecoder(bytes.NewReader(xmlData))
	var buffer bytes.Buffer
	encoder := xml.NewEncoder(&buffer)
	//encoder.Indent("", "  ") // Set indentation to two spaces

	var inElement string
	for {
		t, err := decoder.Token()
		if err != nil {
			break
		}

		switch se := t.(type) {
		case xml.StartElement:
			inElement = se.Name.Local
			encoder.EncodeToken(se)
		case xml.EndElement:
			inElement = ""
			encoder.EncodeToken(se)
		case xml.CharData:
			if inElement == "contractID" {
				se = xml.CharData(contractID)
			}
			encoder.EncodeToken(se)
		default:
			encoder.EncodeToken(t)
		}
	}

	encoder.Flush()

	// Replace tab characters with spaces
	updatedXML := strings.ReplaceAll(buffer.String(), "&#x9;", "	")

	return os.WriteFile(filePath, []byte(updatedXML), 0644)
}

func apiRequestHandler(filename string, isFollowup bool, contractID string) *PendingTransaction {
	// Load PFX certificate
	pfxData, err := os.ReadFile(cfg.PfxPath)
	if err != nil {
		log.Printf("Failed to read PFX file: %v", err)
		return nil
	}

	// Create TLS certificate from PFX
	priv, cert, err := pkcs12.Decode(pfxData, cfg.PfxPassword)
	if err != nil {
		log.Printf("Failed to parse PFX file: %v", err)
		return nil
	}
	tlsCert := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  priv,
		Leaf:        cert,
	}

	// Create custom HTTP client with certificate
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{tlsCert},
			},
		},
	}

	// Read the XML file content
	filePath := filepath.Join(cfg.FolderPath, filename)
	xmlData, err := os.ReadFile(filePath)
	if err != nil {
		log.Printf("Failed to read file %s: %v", filename, err)
		return nil
	}

	// Modified POST request using custom client
	req, err := http.NewRequest("POST", cfg.APIEndpoint, bytes.NewReader(xmlData))
	if err != nil {
		log.Printf("Failed to create request for file %s: %v", filename, err)
		return nil
	}
	req.Header.Set("Content-Type", "text/xml")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to send POST request for file %s: %v", filename, err)
		return nil
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read response for file %s: %v", filename, err)
		return nil
	}

	// Extract transactionID from XML response
	var responseData struct {
		XMLName                  xml.Name `xml:"AddContractSyncResponseBatchXML"`
		AddContractSyncResposnse struct {
			AddContractSyncResponse struct {
				TransactionID  string `xml:"transactionID"`
				ResponseStatus string `xml:"responseStatus"`
			} `xml:"AddContractSyncResponse"`
		} `xml:"addContractSyncResponse"`
	}
	if err := xml.Unmarshal(responseBody, &responseData); err != nil {
		log.Printf("Failed to parse transactionID from response %s: %v", filename, err)
		return nil
	}

	transaction := &PendingTransaction{
		FileName:      filename,
		TransactionID: responseData.AddContractSyncResposnse.AddContractSyncResponse.TransactionID,
		IsFollowup:    isFollowup,
		ContractID:    contractID,
	}

	log.Printf("Processed file %s, transaction ID: %s", filename,
		responseData.AddContractSyncResposnse.AddContractSyncResponse.TransactionID)

	return transaction
}

func CsvWriter(transaction PendingTransaction, contractID string) {
	// Append to CSV file
	csvFile, err := os.OpenFile(cfg.ResponsesFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Failed to open CSV file for file %s: %v", transaction.FileName, err)
		return
	}
	defer csvFile.Close()

	writer := csv.NewWriter(csvFile)
	defer writer.Flush()

	// Write file name, transaction ID, and contract ID to CSV
	if err := writer.Write([]string{
		transaction.FileName,
		transaction.TransactionID,
		contractID,
	}); err != nil {
		log.Printf("Failed to write to CSV for file %s: %v", transaction.FileName, err)
		return
	}
}

func queryAWSData(ctx context.Context, cfg Config, transactionID string) (string, error) {
	// Load AWS configuration with credentials
	awsCfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(cfg.AWSRegion),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			cfg.AWSAccessKey,
			cfg.AWSSecretKey,
			cfg.AWSSessionToken,
		)),
	)
	if err != nil {
		return "", fmt.Errorf("unable to load AWS SDK config: %v", err)
	}

	// Create CloudWatch Logs client
	cwl := cloudwatchlogs.NewFromConfig(awsCfg)

	// Add timeout logic
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	log.Printf("Looking for Contract in AWS")

	for {
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("timeout waiting for contract ID")
		case <-time.After(20 * time.Second):
			// Create the query input
			queryString := fmt.Sprintf(`fields ObjJson.addContractAsyncResponse.transactionId, ObjJson.addContractAsyncResponse.results.contract.contractID | parse @message /.*ObjJson.addContractAsyncResponse.results.contract.contractID=(?<ContractID>[\w-]+)/ | filter ObjJson.addContractAsyncResponse.transactionId in ['%s'] and not isempty(ObjJson.addContractAsyncResponse.results.contract.contractID ) | sort @timestamp desc | limit 20`,
				transactionID)

			startQuery, err := cwl.StartQuery(ctx, &cloudwatchlogs.StartQueryInput{
				LogGroupName: aws.String(cfg.LogGroupName),
				StartTime:    aws.Int64(time.Now().Add(-1 * time.Hour).Unix()), // Search last hour
				EndTime:      aws.Int64(time.Now().Unix()),
				QueryString:  aws.String(queryString),
			})
			if err != nil {
				return "", fmt.Errorf("failed to start CloudWatch query: %v", err)
			}

			// Poll for results
			results, err := cwl.GetQueryResults(ctx, &cloudwatchlogs.GetQueryResultsInput{
				QueryId: startQuery.QueryId,
			})
			if err != nil {
				return "", fmt.Errorf("failed to get query results: %v", err)
			}

			for results.Status == types.QueryStatusRunning {
				time.Sleep(5 * time.Second)
				results, err = cwl.GetQueryResults(ctx, &cloudwatchlogs.GetQueryResultsInput{
					QueryId: startQuery.QueryId,
				})
				if err != nil {
					return "", fmt.Errorf("failed to get query results: %v", err)
				}
			}

			// If we find a ContractID, return it
			if results.Status == types.QueryStatusComplete && len(results.Results) > 0 {
				for _, field := range results.Results[0] {
					if *field.Field == "ObjJson.addContractAsyncResponse.results.contract.contractID" {
						return *field.Value, nil
					}
				}
			}
		}
	}
}
