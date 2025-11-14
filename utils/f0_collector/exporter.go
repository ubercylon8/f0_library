package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
)

// ElasticsearchExporter exports test results to Elasticsearch
type ElasticsearchExporter struct {
	config *ElasticsearchConfig
	client *elasticsearch.Client
	logger *Logger
}

// NewElasticsearchExporter creates a new Elasticsearch exporter
func NewElasticsearchExporter(config *ElasticsearchConfig, logger *Logger) *ElasticsearchExporter {
	return &ElasticsearchExporter{
		config: config,
		logger: logger,
	}
}

// Initialize initializes the Elasticsearch client
func (e *ElasticsearchExporter) Initialize() error {
	cfg := elasticsearch.Config{
		Addresses: e.config.Endpoints,
	}

	// Cloud ID takes precedence
	if e.config.CloudID != "" {
		cfg.CloudID = e.config.CloudID
	}

	// Authentication
	if e.config.APIKey != "" {
		cfg.APIKey = e.config.APIKey
	} else if e.config.Username != "" && e.config.Password != "" {
		cfg.Username = e.config.Username
		cfg.Password = e.config.Password
	}

	// TLS configuration
	// Note: Custom TLS cert configuration would go here

	// Create client
	client, err := elasticsearch.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("failed to create Elasticsearch client: %w", err)
	}

	e.client = client
	e.logger.Info("Elasticsearch client initialized")

	return nil
}

// TestConnection tests connectivity to Elasticsearch
func (e *ElasticsearchExporter) TestConnection() error {
	if e.client == nil {
		if err := e.Initialize(); err != nil {
			return err
		}
	}

	// Ping Elasticsearch
	res, err := e.client.Info()
	if err != nil {
		return fmt.Errorf("failed to connect to Elasticsearch: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("Elasticsearch returned error: %s", res.Status())
	}

	e.logger.Info("Elasticsearch connection test successful")
	return nil
}

// ExportResult exports a single test result to Elasticsearch
func (e *ElasticsearchExporter) ExportResult(result *TestResult, filePath string) error {
	if e.client == nil {
		if err := e.Initialize(); err != nil {
			return err
		}
	}

	// Enrich with collection metadata
	enriched := e.enrichResult(result, filePath)

	// Generate document ID
	docID := e.generateDocumentID(result)

	// Get index name
	indexName := e.getIndexName()

	// Marshal to JSON
	data, err := json.Marshal(enriched)
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	// Index document
	req := esapi.IndexRequest{
		Index:      indexName,
		DocumentID: docID,
		Body:       bytes.NewReader(data),
		Refresh:    "false",
		Timeout:    time.Duration(e.config.Timeout) * time.Second,
	}

	res, err := req.Do(context.Background(), e.client)
	if err != nil {
		return fmt.Errorf("failed to index document: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("Elasticsearch indexing error: %s", res.Status())
	}

	e.logger.Debugf("Indexed document %s to %s", docID, indexName)
	return nil
}

// ExportBatch exports multiple test results in a bulk operation
func (e *ElasticsearchExporter) ExportBatch(results []*TestResult, filePaths []string) error {
	if e.client == nil {
		if err := e.Initialize(); err != nil {
			return err
		}
	}

	if len(results) == 0 {
		return nil
	}

	// Build bulk request body
	var buf bytes.Buffer

	for i, result := range results {
		// Enrich with collection metadata
		enriched := e.enrichResult(result, filePaths[i])

		// Generate document ID
		docID := e.generateDocumentID(result)

		// Get index name
		indexName := e.getIndexName()

		// Bulk index action
		meta := map[string]interface{}{
			"index": map[string]interface{}{
				"_index": indexName,
				"_id":    docID,
			},
		}

		metaJSON, _ := json.Marshal(meta)
		buf.Write(metaJSON)
		buf.WriteByte('\n')

		// Document
		docJSON, err := json.Marshal(enriched)
		if err != nil {
			e.logger.Warnf("Failed to marshal result %s: %v", result.TestID, err)
			continue
		}

		buf.Write(docJSON)
		buf.WriteByte('\n')
	}

	// Send bulk request
	res, err := e.client.Bulk(
		bytes.NewReader(buf.Bytes()),
		e.client.Bulk.WithContext(context.Background()),
		e.client.Bulk.WithTimeout(time.Duration(e.config.Timeout)*time.Second),
	)
	if err != nil {
		return fmt.Errorf("failed to execute bulk request: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("bulk request failed: %s", res.Status())
	}

	// Parse response
	var bulkRes map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&bulkRes); err != nil {
		return fmt.Errorf("failed to parse bulk response: %w", err)
	}

	// Check for errors
	if bulkRes["errors"].(bool) {
		e.logger.Warn("Bulk request completed with some errors")
		// TODO: Handle partial failures
	} else {
		e.logger.Infof("Successfully exported %d document(s)", len(results))
	}

	return nil
}

// enrichResult adds collection metadata to the test result
func (e *ElasticsearchExporter) enrichResult(result *TestResult, filePath string) map[string]interface{} {
	// Convert TestResult to map
	data, _ := json.Marshal(result)
	var enriched map[string]interface{}
	json.Unmarshal(data, &enriched)

	// Get hostname
	hostname, _ := os.Hostname()

	// Add collection metadata
	enriched["collectionMetadata"] = map[string]interface{}{
		"collectedAt":      time.Now().UTC().Format(time.RFC3339),
		"collectorVersion": VERSION,
		"collectorHost":    hostname,
		"filePath":         filePath,
	}

	// Add @timestamp for Kibana
	enriched["@timestamp"] = result.StartTime

	return enriched
}

// generateDocumentID generates a unique document ID
func (e *ElasticsearchExporter) generateDocumentID(result *TestResult) string {
	// Use testId + executionId + startTime for uniqueness
	var executionID string
	if result.ExecutionContext != nil {
		if id, ok := result.ExecutionContext["executionId"].(string); ok {
			executionID = id
		}
	}

	// Generate hash
	data := fmt.Sprintf("%s-%s-%s", result.TestID, executionID, result.StartTime)
	hash := sha256.Sum256([]byte(data))

	return fmt.Sprintf("%x", hash[:16]) // Use first 16 bytes
}

// getIndexName returns the index name based on pattern
func (e *ElasticsearchExporter) getIndexName() string {
	// Parse index pattern
	pattern := e.config.IndexPattern
	if pattern == "" {
		pattern = e.config.IndexPrefix + "-{yyyy.MM.dd}"
	}

	// Replace date placeholders
	now := time.Now().UTC()
	indexName := strings.ReplaceAll(pattern, "{yyyy.MM.dd}", now.Format("2006.01.02"))
	indexName = strings.ReplaceAll(indexName, "{yyyy.MM}", now.Format("2006.01"))
	indexName = strings.ReplaceAll(indexName, "{yyyy}", now.Format("2006"))

	return indexName
}
