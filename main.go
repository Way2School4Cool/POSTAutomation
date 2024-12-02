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
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	//openssl pkcs12 -export -inkey mykey.pem -in mycert.pem -out output.p12 -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -export -macalg sha1

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go/aws"
	"golang.org/x/crypto/pkcs12"
)

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

	for {
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("timeout waiting for contract ID")
		case <-time.After(20 * time.Second):
			// Create the query input
			queryString := fmt.Sprintf(`
				fields ObjJson.addContractAsyncResponse.transactionID, 
				fields ObjJson.addContractAsyncResponse.results.contact.contractID 
				| parse @message /.*ObjJson.addContractAsyncResponse.results.contact.contractID=(?<ContractID[\w-]+)/ 
				| filter ObjJson.addContractAsyncResponse.transactionID in ['%s'] 
				and not isempty(ObjJson.addContractAsyncResponse.results.contact.contractID) 
				| sort @timestamp desc`,
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

			// If we find a ContractID, return it
			if results.Status == types.QueryStatusComplete && len(results.Results) > 0 {
				for _, field := range results.Results[0] {
					if *field.Field == "ContractID" {
						return *field.Value, nil
					}
				}
			}
		}
	}
}

func main() {
	// Load configuration
	cfg := loadConfig()

	// Load PFX certificate
	pfxData, err := os.ReadFile(cfg.PfxPath)
	if err != nil {
		log.Fatalf("Failed to read PFX file: %v", err)
	}

	// Create TLS certificate from PFX
	priv, cert, err := pkcs12.Decode(pfxData, cfg.PfxPassword)
	if err != nil {
		log.Fatalf("Failed to parse PFX file: %v", err)
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

	// Walk through the folder recursively
	var files []os.DirEntry
	err = filepath.WalkDir(cfg.FolderPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			files = append(files, d)
		}
		return nil
	})
	if err != nil {
		log.Fatalf("Failed to walk through folder: %v", err)
	}

	// Create slice to store pending transactions
	var pendingTransactions []PendingTransaction

	// First pass: Process all files and collect transaction IDs
	for _, file := range files {
		// Skip if it's not an XML file
		if filepath.Ext(file.Name()) != ".xml" {
			log.Printf("Skipping non-XML file: %s", file.Name())
			continue
		}

		// Read the XML file content
		filePath := filepath.Join(cfg.FolderPath, file.Name())
		xmlData, err := os.ReadFile(filePath)
		if err != nil {
			log.Printf("Failed to read file %s: %v", file.Name(), err)
			continue
		}

		// Modified POST request using custom client
		req, err := http.NewRequest("POST", cfg.APIEndpoint, bytes.NewReader(xmlData))
		if err != nil {
			log.Printf("Failed to create request for file %s: %v", file.Name(), err)
			continue
		}
		req.Header.Set("Content-Type", "text/xml")

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("Failed to send POST request for file %s: %v", file.Name(), err)
			continue
		}
		defer resp.Body.Close()

		responseBody, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("Failed to read response for file %s: %v", file.Name(), err)
			continue
		}

		// Extract contractID from XML request
		var requestData struct {
			ContractID string `xml:"contractID"`
		}
		if err := xml.Unmarshal(xmlData, &requestData); err != nil {
			log.Printf("Failed to parse contractID from request %s: %v", file.Name(), err)
			continue
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
			log.Printf("Failed to parse transactionID from response %s: %v", file.Name(), err)
			continue
		}

		// After getting response, store transaction info instead of querying AWS
		pendingTransactions = append(pendingTransactions, PendingTransaction{
			FileName:      file.Name(),
			TransactionID: responseData.AddContractSyncResposnse.AddContractSyncResponse.TransactionID,
		})

		log.Printf("Processed file %s, stored transaction ID: %s", file.Name(),
			responseData.AddContractSyncResposnse.AddContractSyncResponse.TransactionID)
	}

	// Second pass: Query AWS for all pending transactions
	log.Printf("Starting AWS queries for %d transactions", len(pendingTransactions))
	for _, transaction := range pendingTransactions {
		contractID, err := queryAWSData(context.Background(), cfg, transaction.TransactionID)
		if err != nil {
			log.Printf("Failed to query AWS for transactionID %s: %v",
				transaction.TransactionID, err)
			continue
		}

		// Append to CSV file
		csvFile, err := os.OpenFile(cfg.ResponsesFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Printf("Failed to open CSV file for file %s: %v", transaction.FileName, err)
			continue
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
			continue
		}

		log.Printf("Processed file %s and saved response to CSV with ContractID: %s", transaction.FileName, contractID)
	}
}
