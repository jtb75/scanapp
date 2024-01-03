// File: pkg/wizapi/wizapi.go

package wizapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"scanapp/pkg/config"
	"time"
)

// Resource query validation
const graphResourceSearchQuery = `
query GraphSearch($query: GraphEntityQueryInput, $controlId: ID, $projectId: String!, $first: Int, $after: String, $fetchTotalCount: Boolean!, $quick: Boolean = true, $fetchPublicExposurePaths: Boolean = false, $fetchInternalExposurePaths: Boolean = false, $fetchIssueAnalytics: Boolean = false, $fetchLateralMovement: Boolean = false, $fetchKubernetes: Boolean = false) {
	graphSearch(
	  query: $query
	  controlId: $controlId
	  projectId: $projectId
	  first: $first
	  after: $after
	  quick: $quick
	) {
	  totalCount @include(if: $fetchTotalCount)
	  maxCountReached @include(if: $fetchTotalCount)
	  pageInfo {
		endCursor
		hasNextPage
	  }
	  nodes {
		entities {
		  ...PathGraphEntityFragment
		  userMetadata {
			isInWatchlist
			isIgnored
			note
		  }
		  technologies {
			id
			icon
		  }
		  publicExposures(first: 10) @include(if: $fetchPublicExposurePaths) {
			nodes {
			  ...NetworkExposureFragment
			}
		  }
		  otherSubscriptionExposures(first: 10) @include(if: $fetchInternalExposurePaths) {
			nodes {
			  ...NetworkExposureFragment
			}
		  }
		  otherVnetExposures(first: 10) @include(if: $fetchInternalExposurePaths) {
			nodes {
			  ...NetworkExposureFragment
			}
		  }
		  lateralMovementPaths(first: 10) @include(if: $fetchLateralMovement) {
			nodes {
			  id
			  pathEntities {
				entity {
				  ...PathGraphEntityFragment
				}
			  }
			}
		  }
		  kubernetesPaths(first: 10) @include(if: $fetchKubernetes) {
			nodes {
			  id
			  path {
				...PathGraphEntityFragment
			  }
			}
		  }
		}
		aggregateCount
	  }
	}
  }
  
	  fragment PathGraphEntityFragment on GraphEntity {
	id
	name
	type
	properties
	issueAnalytics: issues(filterBy: {status: [IN_PROGRESS, OPEN]}) @include(if: $fetchIssueAnalytics) {
	  highSeverityCount
	  criticalSeverityCount
	}
  }
  
  
	  fragment NetworkExposureFragment on NetworkExposure {
	id
	portRange
	sourceIpRange
	destinationIpRange
	path {
	  ...PathGraphEntityFragment
	}
	applicationEndpoints {
	  ...PathGraphEntityFragment
	}
  }
`

// Query to Post for upload of new vulnerability content
const graphFileUploadRequest = `
query RequestSecurityScanUpload($filename: String!) {
	requestSecurityScanUpload(filename: $filename) {
	  upload {
		id
		url
		systemActivityId
	  }
	}
}
`

// Query to check System Activity
const graphSystemActivityQuery = `
query SystemActivity($id: ID!) {
	systemActivity(id: $id) {
		id
		status
		statusInfo
		result {
		  ...on SystemActivityEnrichmentIntegrationResult{
			dataSources {
			  ... IngestionStatsDetails
			}
			findings {
			  ... IngestionStatsDetails
			}
			events {
			  ... IngestionStatsDetails
			}
			tags {
			  ... IngestionStatsDetails
			}
			unresolvedAssets {
			  ... UnresolvedAssetsDetails
			}
		  }
		}
		context {
		  ... on SystemActivityEnrichmentIntegrationContext{
			fileUploadId
		  }
		}
	}
  }
fragment IngestionStatsDetails on EnrichmentIntegrationStats {
	incoming
	handled
}

fragment UnresolvedAssetsDetails on EnrichmentIntegrationUnresolvedAssets {
	count
	ids
}
`

// RequestSecurityScanUploadResponse represents the response structure for the RequestSecurityScanUpload query
type RequestSecurityScanUploadResponse struct {
	Data struct {
		RequestSecurityScanUpload struct {
			Upload struct {
				ID               string `json:"id"`
				URL              string `json:"url"`
				SystemActivityId string `json:"systemActivityId"`
			} `json:"upload"`
		} `json:"requestSecurityScanUpload"`
	} `json:"data"`
	Errors []GraphQLResourceError `json:"errors"` // Reuse the existing error struct
}

// SystemActivityResponse is the expected response from the SystemActivity GraphQL query
type SystemActivityResponse struct {
	Data struct {
		SystemActivity struct {
			ID         string `json:"id"`
			Status     string `json:"status"`
			StatusInfo string `json:"statusInfo"`
			Result     struct {
				DataSources      IngestionStatsDetails `json:"dataSources"`
				Findings         IngestionStatsDetails `json:"findings"`
				Events           IngestionStatsDetails `json:"events"`
				Tags             IngestionStatsDetails `json:"tags"`
				UnresolvedAssets struct {
					Count int      `json:"count"`
					IDs   []string `json:"ids"`
				} `json:"unresolvedAssets"`
			} `json:"result"`
			Context struct {
				FileUploadId string `json:"fileUploadId"`
			} `json:"context"`
		} `json:"systemActivity"`
	} `json:"data"`
	Errors []GraphQLResourceError `json:"errors"`
}

type IngestionStatsDetails struct {
	Incoming int `json:"incoming"`
	Handled  int `json:"handled"`
}

type GraphQLResourceResponse struct {
	Data struct {
		GraphSearch struct {
			MaxCountReached bool `json:"maxCountReached"`
			TotalCount      int  `json:"totalCount"` // TotalCount is now directly mapped
			Nodes           []struct {
				AggregateCount interface{} `json:"aggregateCount"`
				Entities       []struct {
					ID           string                 `json:"id"`
					Name         string                 `json:"name"`
					Properties   map[string]interface{} `json:"properties"`
					Technologies []struct {
						ID   string `json:"id"`
						Icon string `json:"icon"`
					} `json:"technologies"`
					Type         string      `json:"type"`
					UserMetadata interface{} `json:"userMetadata"`
				} `json:"entities"`
			} `json:"nodes"`
			PageInfo struct {
				EndCursor   string `json:"endCursor"`
				HasNextPage bool   `json:"hasNextPage"`
			} `json:"pageInfo"`
		} `json:"graphSearch"`
	} `json:"data"`
	Errors []GraphQLResourceError `json:"errors"`
}

type GraphQLResourceError struct {
	Message string `json:"message"`
}

// GraphQLRequest represents a request to a GraphQL API.
type GraphQLRequest struct {
	Query     string                 `json:"query"`     // The GraphQL query string
	Variables map[string]interface{} `json:"variables"` // Any variables used in the query
}

// WizAPI struct holds the necessary information to interact with the WizAPI
type WizAPI struct {
	Session        *http.Client      // HTTP client to make requests
	AuthToken      string            // Auth token received after successful authentication
	WizAPI         map[string]string // Miscellaneous configurations
	ClientID       string            // Client ID for WizAPI
	ClientSecret   string            // Client Secret for WizAPI
	ClientAuthURL  string            // Authentication URL for WizAPI
	ClientQueryURL string            // Query URL for WizAPI
}

// NewWizAPI creates and returns a new instance of WizAPI
func NewWizAPI(clientID, clientSecret, clientAuthURL, clientQueryURL string) *WizAPI {
	return &WizAPI{
		Session: &http.Client{Timeout: 60 * time.Second},
		WizAPI: map[string]string{
			"proxy":           "",    // Define if any proxy is used
			"wiz_req_timeout": "300", // Request timeout in seconds
		},
		ClientID:       clientID,
		ClientSecret:   clientSecret,
		ClientAuthURL:  clientAuthURL,
		ClientQueryURL: clientQueryURL,
	}
}

// Authenticate authenticates with the WizAPI and stores the auth token
func (w *WizAPI) Authenticate() error {
	// Construct the request data
	requestData := url.Values{}
	requestData.Set("audience", "wiz-api")
	requestData.Set("grant_type", "client_credentials")
	requestData.Set("client_id", w.ClientID)
	requestData.Set("client_secret", w.ClientSecret)

	// Send a POST request to the Wiz API authentication endpoint
	response, err := w.Session.PostForm(w.ClientAuthURL, requestData)
	if err != nil {
		return fmt.Errorf("error authenticating to the Wiz API: %w", err)
	}
	defer response.Body.Close()

	// Handle non-200 status
	if response.StatusCode != 200 {
		body, _ := io.ReadAll(response.Body)
		return fmt.Errorf("authentication failed with status: %s - %s", response.Status, string(body))
	}

	// Decode the response
	var responseData map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&responseData); err != nil {
		return fmt.Errorf("error parsing authentication response: %w", err)
	}

	// Extract the access token from the response
	token, ok := responseData["access_token"].(string)
	if !ok {
		return errors.New("no access token found in the response")
	}

	// Store the access token
	w.AuthToken = token
	return nil
}

func (w *WizAPI) GraphResourceSearch(cfg *config.Config) (*GraphQLResourceResponse, error) {
	queryVariables := resourceCreateQueryVariables(cfg.ScanCloudType, cfg.ScanProviderID)
	query := graphResourceSearchQuery // Your GraphQL query

	response, err := w.QueryWithRetry(query, queryVariables)
	if err != nil {
		return nil, fmt.Errorf("error querying with retry: %w", err)
	}

	// Process the HTTP response and unmarshal the JSON into GraphQLResourceResponse
	var graphQLResourceResponse GraphQLResourceResponse
	if err := json.NewDecoder(response.Body).Decode(&graphQLResourceResponse); err != nil {
		return nil, fmt.Errorf("error unmarshaling response: %w", err)
	}

	if len(graphQLResourceResponse.Errors) > 0 {
		return nil, fmt.Errorf("graphql errors: %v", graphQLResourceResponse.Errors)
	}

	return &graphQLResourceResponse, nil
}

func resourceCreateQueryVariables(scanCloudType, scanProviderID string) map[string]interface{} {
	return map[string]interface{}{
		"quick": true,
		"first": 50,
		"query": map[string]interface{}{
			"type":   []string{"VIRTUAL_MACHINE"},
			"select": true,
			"where": map[string]interface{}{
				"cloudPlatform": map[string]interface{}{
					"EQUALS": []string{scanCloudType},
				},
				"externalId": map[string]interface{}{
					"EQUALS": []string{scanProviderID},
				},
			},
		},
		"projectId":       "*",
		"fetchTotalCount": true,
	}
}

// QueryWithRetry attempts to send a GraphQL query and retries if certain conditions are met.
func (w *WizAPI) QueryWithRetry(query string, variables map[string]interface{}) (*http.Response, error) {
	// Define how many times you want to retry and the delay between retries
	maxRetries := 3
	retryDelay := time.Second * 2

	// Prepare the request data
	data := map[string]interface{}{
		"query":     query,
		"variables": variables,
	}

	// Convert the data to JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("Error marshaling query data: %s\n", err)
		return nil, err
	}

	// Create the HTTP request
	request, err := http.NewRequest("POST", w.ClientQueryURL, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Error creating request: %s\n", err)
		return nil, err
	}

	// Set necessary headers
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", w.AuthToken))
	request.Header.Add("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")

	// Initialize response variable
	var response *http.Response

	// Attempt the request with retries
	for attempt := 0; attempt < maxRetries; attempt++ {
		response, err = w.Session.Do(request)
		if err != nil {
			log.Printf("Error querying Wiz API: %s\n", err)
			time.Sleep(retryDelay) // Wait before retrying
			continue               // Proceed to the next attempt
		}

		// If the status code is not one of the retryable ones, break the loop
		if !w.RetryableResponseStatusCode(response.StatusCode) {
			break
		}

		// Close the previous response body to avoid leaks
		if response.Body != nil {
			response.Body.Close()
		}

		log.Printf("Retrying due to status code: %d, attempt: %d\n", response.StatusCode, attempt+1)
		time.Sleep(retryDelay) // Wait before retrying
	}

	// After the loop, check why the function exited the loop
	if err != nil {
		// If there was an error in the last attempt, return it
		return nil, err
	} else if response != nil && !w.RetryableResponseStatusCode(response.StatusCode) {
		// If the last response had a non-retryable status code, return the response
		return response, nil
	}

	// If none of the above conditions were met, it means all retries were exhausted
	return nil, fmt.Errorf("max retries reached with status code: %d", response.StatusCode)
}

// RetryableResponseStatusCode determines whether a given HTTP status code is retryable
func (w *WizAPI) RetryableResponseStatusCode(statusCode int) bool {
	// Define which status codes are considered retryable
	switch statusCode {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

// RequestSecurityScanUpload sends a query to request a security scan upload URL and ID for a file
func (w *WizAPI) RequestSecurityScanUpload(filename string) (*RequestSecurityScanUploadResponse, error) {
	// Prepare the variables for the query
	variables := map[string]interface{}{
		"filename": filename,
	}

	// Execute the query using the constant graphFileUploadRequest
	response, err := w.QueryWithRetry(graphFileUploadRequest, variables)
	if err != nil {
		return nil, fmt.Errorf("error querying with retry: %w", err)
	}

	// Process the HTTP response and unmarshal the JSON into RequestSecurityScanUploadResponse
	var uploadResponse RequestSecurityScanUploadResponse
	if err := json.NewDecoder(response.Body).Decode(&uploadResponse); err != nil {
		return nil, fmt.Errorf("error unmarshaling response: %w", err)
	}

	// Handle any errors in the response
	if len(uploadResponse.Errors) > 0 {
		return nil, fmt.Errorf("graphql errors: %v", uploadResponse.Errors)
	}

	return &uploadResponse, nil
}

// QuerySystemActivity performs the SystemActivity GraphQL query with the given ID.
func (w *WizAPI) QuerySystemActivity(systemActivityID string) (*SystemActivityResponse, error) {
	// Prepare the variables for the query
	variables := map[string]interface{}{
		"id": systemActivityID,
	}

	// Use QueryWithRetry to perform the query with built-in retry logic
	response, err := w.QueryWithRetry(graphSystemActivityQuery, variables)
	if err != nil {
		return nil, fmt.Errorf("error querying system activity with retry: %w", err)
	}
	defer response.Body.Close()

	// Decode the response into the SystemActivityResponse struct
	var systemActivityResponse SystemActivityResponse
	if err := json.NewDecoder(response.Body).Decode(&systemActivityResponse); err != nil {
		return nil, fmt.Errorf("error unmarshaling response: %w", err)
	}

	// Check for GraphQL errors
	if len(systemActivityResponse.Errors) > 0 {
		return nil, fmt.Errorf("graphql errors: %v", systemActivityResponse.Errors)
	}

	// Return the parsed response
	return &systemActivityResponse, nil
}
