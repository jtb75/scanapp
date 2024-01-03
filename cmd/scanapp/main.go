package main

import (
	"fmt"
	"os"
	"scanapp/pkg/aws"
	"scanapp/pkg/config" // Adjust the import path based on your module's name and structure
	"scanapp/pkg/wizapi" // Adjust the import path based on your module's name and structure
	"strings"
	"time"
)

func main() {
	// Parse the command-line arguments and get the configuration
	var cfg *config.Config
	var err error
	configFilePath := "config.json" // Set this to your default or obtain it from args

	// Parse the command-line arguments and get the configuration
	if len(os.Args) > 1 {
		cfg, configFilePath = config.ParseArgs()

		// Validate the provided configuration
		if err := cfg.Validate(); err != nil {
			fmt.Printf("Configuration validation error: %v\n", err)
			os.Exit(1)
		}

		// If the save flag is set, save the current configuration to the file
		if cfg.Save {
			if err := config.SaveConfig(cfg, configFilePath); err != nil {
				fmt.Printf("Failed to save configuration to '%s': %v\n", configFilePath, err)
				os.Exit(1)
			}
			fmt.Printf("Configuration saved successfully to '%s'.\n", configFilePath)
		}
	} else {
		// If no flags are provided, try reading the configuration from the file
		cfg, err = config.ReadConfig(configFilePath)
		if err != nil {
			fmt.Printf("Error reading config from file '%s': %v\n", configFilePath, err)
			os.Exit(1)
		}
	}
	/*
		wizCliPath, err := wizcli.SetupEnvironment()
		if err != nil {
			fmt.Println("Failed to set up wizcli environment:", err)
			return
		}
		defer func() {
			if err := wizcli.CleanupEnvironment(wizCliPath); err != nil {
				fmt.Println("Warning: Failed to clean up environment:", err)
			}
		}()

		// Set the WIZ_DIR environment variable to the directory holding wizcli
		wizDir := filepath.Dir(wizCliPath)
		if err := os.Setenv("WIZ_DIR", wizDir); err != nil {
			fmt.Println("Failed to set WIZ_DIR environment variable:", err)
			return
		}
		fmt.Printf("WIZ_DIR set to: %s\n", wizDir)

		// Authenticate wizcli using the credentials from the config
		authMessage, err := wizcli.AuthenticateWizcli(wizCliPath, cfg.WizClientID, cfg.WizClientSecret)
		if err != nil {
			fmt.Println("Failed to authenticate wizcli:", err)
			return
		}

		fmt.Println(authMessage)
		fmt.Println("wizcli is set up and authenticated at:", wizCliPath)

		// Use the appropriate root path or leave empty for Windows
		rootPath := "/"
		if runtime.GOOS == "windows" {
			rootPath = ""
		}

		// Get top level directories
		directories, err := environment.ListTopLevelDirectories(rootPath)
		if err != nil {
			fmt.Println("Error listing directories:", err)
			return
		}

		fmt.Println("Top-level directories:")
		directories = []string{"/tmp/scandir"}
		for _, dir := range directories {
			fmt.Println(dir)
		}
	*/
	// Initialize WizAPI client
	apiClient := wizapi.NewWizAPI(cfg.WizClientID, cfg.WizClientSecret, cfg.WizAuthURL, cfg.WizQueryURL)

	// Authenticate with the WizAPI
	if err := apiClient.Authenticate(); err != nil {
		fmt.Println("Failed to authenticate with WizAPI:", err)
		return
	}
	fmt.Println("Authenticated with WizAPI successfully")
	/*
		   // Call GraphResourceSearch to execute the GraphQL query
		   graphQLResourceResponse, err := apiClient.GraphResourceSearch(cfg)

		   	if err != nil {
		   		fmt.Println("Error executing GraphResourceSearch:", err)
		   		return
		   	}

		   // Process the GraphQL response as needed
		   // graphQLResponse contains the result of the query
		   fmt.Println("Total Resource Count:", graphQLResourceResponse.Data.GraphSearch.TotalCount)
		   // Exit if the resource does not equal exactly 1

		   	if graphQLResourceResponse.Data.GraphSearch.TotalCount != 1 {
		   		fmt.Println("Total Resource Count is not equal to 1. Exiting...")
		   		os.Exit(1) // Exit with a non-zero status code to indicate an error
		   	}

		   // Handle any errors in the response

		   	if len(graphQLResourceResponse.Errors) > 0 {
		   		fmt.Println("GraphQL errors:", graphQLResourceResponse.Errors)
		   		return
		   	}

		   	jsonOutputs, err := wizcli.ScanDirectories(directories, wizCliPath)

		   		if err != nil {
		   			fmt.Println("Error scanning directories:", err)
		   			return // or handle the error as needed
		   		}

		   	historicalState, err := vulnerability.OpenHistoricalState()

		   		if err != nil {
		   			fmt.Println("Error opening historical state:", err)
		   			return
		   		}

		   	// Process the data
		   	currentState, err := vulnerability.ProcessVulnerabilities(jsonOutputs, cfg, historicalState)

		   		if err != nil {
		   			fmt.Println("Failed to transform scan results to payload:", err)
		   		}

		   	// Check if either currentState or historicalState is empty

		   		if currentState == nil || len(currentState.DataSources) == 0 || historicalState == nil || len(historicalState.DataSources) == 0 {
		   			fmt.Println("Error: Both historicalState and currentState must be populated")
		   			return // terminate the program
		   		}

		   	// Update the historical state with any new findings from the current state
		   	updatedHistoricalState, err := vulnerability.UpdateHistoricalState(historicalState, currentState)

		   		if err != nil {
		   			fmt.Println("Error updating historical state:", err)
		   			return
		   		}

		   	// Write historicalState to the file
		   	err = vulnerability.WriteHistoricalState(updatedHistoricalState)

		   		if err != nil {
		   			fmt.Println("Error writing historical state:", err)
		   			return
		   		}

		   	// Write currentState to the file
		   	err = vulnerability.WriteCurrentState(currentState)

		   		if err != nil {
		   			fmt.Println("Error writing current state:", err)
		   			return
		   		}

		   	fmt.Println("Current and historical states written successfully")

		historicalState, err := vulnerability.OpenHistoricalState()

		if err != nil {
			fmt.Println("Error opening historical state:", err)
			return
		}
		currentState, err := vulnerability.OpenCurrentState()

		if err != nil {
			fmt.Println("Error opening current state:", err)
			return
		}

		// Check if either currentState or historicalState is empty

		if currentState == nil || len(currentState.DataSources) == 0 || historicalState == nil || len(historicalState.DataSources) == 0 {
			fmt.Println("Error: Both historicalState and currentState must be populated")
			return // terminate the program
		}
	*/
	// The filename you wish to upload
	filename := "state-current.json"

	// Call RequestSecurityScanUpload to get upload details
	uploadResponse, err := apiClient.RequestSecurityScanUpload(filename)
	if err != nil {
		fmt.Println("Error requesting security scan upload:", err)
		return
	}

	// Process the response as needed
	fmt.Printf("Upload ID: %s\n", uploadResponse.Data.RequestSecurityScanUpload.Upload.ID)
	fmt.Printf("Upload URL: %s\n", uploadResponse.Data.RequestSecurityScanUpload.Upload.URL)
	fmt.Printf("System Activity ID: %s\n", uploadResponse.Data.RequestSecurityScanUpload.Upload.SystemActivityId)

	// Call StateUpload to upload the file
	err = aws.StateUpload(uploadResponse.Data.RequestSecurityScanUpload.Upload.URL, filename)
	if err != nil {
		fmt.Println("Error uploading state file:", err)
		return
	}

	const maxRetries = 5
	const retryDelay = 10 // in seconds

	var systemActivityResponse *wizapi.SystemActivityResponse

	for attempt := 0; attempt < maxRetries; attempt++ {
		systemActivityResponse, err = apiClient.QuerySystemActivity(uploadResponse.Data.RequestSecurityScanUpload.Upload.SystemActivityId)
		if err != nil {
			if strings.Contains(err.Error(), "Resource not found") && attempt < maxRetries-1 {
				fmt.Printf("Resource not found, retrying in %d seconds...\n", retryDelay)
				time.Sleep(time.Duration(retryDelay) * time.Second)
				continue
			} else {
				fmt.Printf("Error querying system activity: %v\n", err)
				return
			}
		}
		break
	}

	if err == nil {
		fmt.Printf("System Activity Status: %s\n", systemActivityResponse.Data.SystemActivity.Status)
		// ... handle other parts of the response as needed ...
	} else {
		fmt.Println("Failed to query system activity after retries.")
	}

}
