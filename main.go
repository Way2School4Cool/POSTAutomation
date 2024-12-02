package main

import (
	"bytes"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"

	//openssl pkcs12 -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -export -macalg sha1

	"golang.org/x/crypto/pkcs12"
)

type Config struct {
	FolderPath    string `json:"folderPath"`
	APIEndpoint   string `json:"apiEndpoint"`
	ResponsesFile string `json:"responsesFile"`
	PfxPath       string `json:"pfxPath"`
	PfxPassword   string `json:"pfxPassword"`
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

	// Open the folder
	files, err := os.ReadDir(cfg.FolderPath)
	if err != nil {
		log.Fatalf("Failed to read folder: %v", err)
	}

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
		req, err := http.NewRequest("POST", cfg.APIEndpoint, bytes.NewBuffer(xmlData))
		if err != nil {
			log.Printf("Failed to create request for file %s: %v", file.Name(), err)
			continue
		}
		req.Header.Set("Content-Type", "application/xml")

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("Failed to send POST request for file %s: %v", file.Name(), err)
			continue
		}
		defer resp.Body.Close()

		// Read and log the response
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
			XMLName                  xml.Name `xml:"AddContractAsyncResponseBatchXML"`
			AddContractAsyncResponse struct {
				AddContractAsyncResponse struct {
					TransactionID  string `xml:"transactionID"`
					ResponseStatus string `xml:"responseStatus"`
				} `xml:"AddContractAsyncResponse"`
			} `xml:"addContractAsyncResponse"`
		}
		if err := xml.Unmarshal(responseBody, &responseData); err != nil {
			log.Printf("Failed to parse transactionID from response %s: %v", file.Name(), err)
			continue
		}

		// Append to CSV file
		csvFile, err := os.OpenFile(cfg.ResponsesFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Printf("Failed to open CSV file for file %s: %v", file.Name(), err)
			continue
		}
		defer csvFile.Close()

		writer := csv.NewWriter(csvFile)
		defer writer.Flush()

		if err := writer.Write([]string{requestData.ContractID, responseData.AddContractAsyncResponse.AddContractAsyncResponse.TransactionID}); err != nil {
			log.Printf("Failed to write to CSV for file %s: %v", file.Name(), err)
			continue
		}

		log.Printf("Processed file %s and saved response to CSV", file.Name())
	}
}
