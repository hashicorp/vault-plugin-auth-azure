package azureauth

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestRotateRootSuccess(t *testing.T) {
	b, s := getTestBackend(t)

	subscriptionID, tenantID, clientID, clientSecret := getAzureEnvironmentSettings()
	if subscriptionID == "" || tenantID == "" ||
		clientID == "" || clientSecret == "" {
		t.Skip("environment variables not set, skipping test in CI")

	}

	configData := map[string]interface{}{
		"subscription_id": subscriptionID,
		"tenant_id":       tenantID,
		"resource":        "https://management.azure.com/",
		"client_id":       clientID,
		"client_secret":   clientSecret,
		"environment":     "AZUREPUBLICCLOUD",
	}
	if err := testConfigCreate(t, b, s, configData); err != nil {
		t.Fatalf("err: %v", err)
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-root",
		Data:      map[string]interface{}{},
		Storage:   s,
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}

	config, err := b.config(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}

	if config.ClientSecret == "" {
		t.Fatal(fmt.Errorf("root password was empty after rotate root, it shouldn't be"))
	}

	if config.NewClientSecret == config.ClientSecret {
		t.Fatal("old and new password equal after rotate-root, it shouldn't be")
	}

	if config.NewClientSecret == "" {
		t.Fatal("new password is empty, it shouldn't be")
	}

	if config.NewClientSecretKeyID == "" {
		t.Fatal("new password key id is empty, it shouldn't be")
	}

	if !b.updatePassword {
		t.Fatal("update password is false, it shouldn't be")
	}

	config.NewClientSecretCreated = config.NewClientSecretCreated.Add(-(time.Minute * 1))
	err = b.saveConfig(context.Background(), config, s)
	if err != nil {
		t.Fatal(err)
	}

	err = b.periodicFunc(context.Background(), &logical.Request{
		Storage: s,
	})

	if err != nil {
		t.Fatal(err)
	}

	newConfig, err := b.config(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}

	if newConfig.ClientSecret != config.NewClientSecret {
		t.Fatal(fmt.Errorf("old and new password aren't equal after periodic function, they should be"))
	}
}

func TestRotateRootPeriodicFunctionBeforeMinute(t *testing.T) {
	// Remove once test has been refactored
	t.Skip()

	b, s := getTestBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-root",
		Data:      map[string]interface{}{},
		Storage:   s,
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}

	tests := []struct {
		Name    string
		Created time.Duration
	}{
		{
			Name:    "1 second test:",
			Created: time.Second * 1,
		},
		{
			Name:    "5 seconds test:",
			Created: time.Second * 5,
		},
		{
			Name:    "30 seconds test:",
			Created: time.Second * 30,
		},
		{
			Name:    "50 seconds test:",
			Created: time.Second * 50,
		},
	}

	for _, test := range tests {
		t.Log(test.Name)
		config, err := b.config(context.Background(), s)
		if err != nil {
			t.Fatal(err)
		}

		config.NewClientSecretCreated = time.Now().Add(-(test.Created))
		err = b.saveConfig(context.Background(), config, s)
		if err != nil {
			t.Fatal(test.Name, err)
		}

		err = b.periodicFunc(context.Background(), &logical.Request{
			Storage: s,
		})

		if err != nil {
			t.Fatal(test.Name, err)
		}

		newConfig, err := b.config(context.Background(), s)
		if err != nil {
			t.Fatal(test.Name, err)
		}

		if newConfig.ClientSecret == config.NewClientSecret {
			t.Fatal(test.Name, fmt.Errorf("old and new password are equal after periodic function, they shouldn't be"))
		}
	}
}

func getAzureEnvironmentSettings() (
	string,
	string,
	string,
	string,
) {
	subscriptionID := os.Getenv("SUBSCRIPTION_ID")
	tenantID := os.Getenv("TENANT_ID")
	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")

	return subscriptionID, tenantID, clientID, clientSecret
}
