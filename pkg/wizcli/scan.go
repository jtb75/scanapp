// wizcli.go (within the wizcli package)

package wizcli

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

// ScanDirectories receives a slice of directory paths and a wizCliPath, then scans each directory.
func ScanDirectories(directories []string, wizCliPath string) ([]string, error) {
	var jsonOutputs []string // Slice to store the JSON outputs

	hostname, err := os.Hostname()
	if err != nil {
		fmt.Println("Error getting hostname:", err)
	}

	for _, dir := range directories {
		fmt.Println("Scanning directory", dir)
		// Concatenate hostname and dir separated by ":"
		scanName := fmt.Sprintf("%s:%s", hostname, dir)

		// Construct the command string
		cmdStr := fmt.Sprintf("%s dir scan --path %s -f json --name %s", wizCliPath, dir, scanName)

		// Execute the command
		cmd := exec.Command("sh", "-c", cmdStr)
		output, err := cmd.CombinedOutput()
		if err != nil {
			// Get the error message as a string
			errMsg := err.Error()

			// Check if the error message is 'exit status 4'
			if errMsg == "exit status 4" {
				// Reset the error to nil since you want to ignore this specific error
				err = nil
			} else {
				// Handle other errors
				return nil, fmt.Errorf("error scanning directory %s: %v", dir, err)
			}
		}

		// Process or log the output as needed
		// Extract the JSON part from the output
		jsonOutput, err := extractJSON(string(output))
		if err != nil {
			log.Printf("Unknown error parsing scan results for directory %s: %v", dir, err)
			continue // Optionally continue to the next directory or return the error based on your requirements
		}

		// Append the JSON output to the slice
		jsonOutputs = append(jsonOutputs, jsonOutput)
	}

	return jsonOutputs, nil // Return the slice of JSON strings and nil as the error
}

// extractJSON takes a string and returns the JSON part of it.
func extractJSON(output string) (string, error) {
	// Find the index of the opening brace of the JSON object
	startIndex := strings.Index(output, "{")
	if startIndex == -1 {
		return "", fmt.Errorf("no opening brace of JSON object found")
	}

	// Find the index of the last closing brace of the JSON object
	endIndex := strings.LastIndex(output, "}")
	if endIndex == -1 {
		return "", fmt.Errorf("no closing brace of JSON object found")
	}

	// Extract the JSON portion
	if endIndex+1 <= startIndex {
		return "", fmt.Errorf("invalid JSON boundaries found")
	}
	jsonPart := output[startIndex : endIndex+1]

	return jsonPart, nil
}
