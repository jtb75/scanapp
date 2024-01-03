package config

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

// Config holds the configuration values
type Config struct {
	WizClientID        string `json:"wizClientId"`
	WizClientSecret    string `json:"wizClientSecret"`
	WizQueryURL        string `json:"wizQueryUrl"`
	WizAuthURL         string `json:"wizAuthUrl"`
	ScanSubscriptionID string `json:"scanSubscriptionId"`
	ScanCloudType      string `json:"scanCloudType"`
	ScanProviderID     string `json:"scanProviderId"`
	Save               bool   `json:"save"`
}

// readConfig reads configuration from a file and unmarshals it into a Config struct
func ReadConfig(filePath string) (*Config, error) {
	file, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var config Config
	err = json.Unmarshal(file, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

// saveConfig saves the configuration from a Config struct to a file in JSON format
func SaveConfig(config *Config, filePath string) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	err = os.WriteFile(filePath, data, 0644)
	if err != nil {
		return err
	}
	return nil
}

// Validate checks the configuration and returns an error if it is invalid
func (c *Config) Validate() error {
	// Implement your validation logic here.
	// For example:
	if c.WizClientID == "" {
		return fmt.Errorf("WizClientID cannot be empty")
	}
	return nil // No error means the configuration is valid
}

// parseArgs parses the command-line arguments and populates the Config struct
func ParseArgs() (*Config, string) {
	cfg := &Config{}
	var configFilePath string

	flag.StringVar(&cfg.WizClientID, "wizClientId", "", "Wiz Client ID")
	flag.StringVar(&cfg.WizClientSecret, "wizClientSecret", "", "Wiz Client Secret")
	flag.StringVar(&cfg.WizQueryURL, "wizQueryUrl", "", "Wiz Query URL")
	flag.StringVar(&cfg.WizAuthURL, "wizAuthUrl", "", "Wiz Auth URL")
	flag.StringVar(&cfg.ScanSubscriptionID, "scanSubscriptionId", "", "Scan Subscription ID")
	flag.StringVar(&cfg.ScanCloudType, "scanCloudType", "", "Scan Cloud Type")
	flag.StringVar(&cfg.ScanProviderID, "scanProviderId", "", "Scan Provider ID")
	flag.BoolVar(&cfg.Save, "save", false, "Set to true to save the configuration")
	flag.StringVar(&configFilePath, "config", "config.json", "Path to the configuration file")

	flag.Parse()

	return cfg, configFilePath
}
