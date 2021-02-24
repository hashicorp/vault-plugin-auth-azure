package azureauth

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/helper/pluginutil"
	"github.com/hashicorp/vault/sdk/version"
	"github.com/ryboe/q"
)

func TestJsonTime(t *testing.T) {
	type a struct {
		Time jsonTime `json:"time"`
	}

	now := time.Now().Round(time.Second)
	test1Raw := fmt.Sprintf(`{"time":%d}`, now.Unix())
	test1 := new(a)
	if err := json.Unmarshal([]byte(test1Raw), test1); err != nil {
		t.Fatalf("err: %v", err)
	}
	if !now.Equal(time.Time(test1.Time)) {
		t.Fatalf("expected: %s, got: %s", now, time.Time(test1.Time))
	}

	test2Raw := fmt.Sprintf(`{"time":%f}`, float64(now.Unix()))
	test2 := new(a)
	if err := json.Unmarshal([]byte(test2Raw), test2); err != nil {
		t.Fatalf("err: %v", err)
	}
	if !now.Equal(time.Time(test2.Time)) {
		t.Fatalf("expected: %s, got: %s", now, time.Time(test2.Time))
	}
}

func TestUserAgent(t *testing.T) {
	// VersionMetadata contains the version of Vault, typically "ent" or "prem" etc
	// for enterprise versions, and "" for OSS version. Dev versions will contain
	// "dev"
	// GUID
	// 15cd22ce-24af-43a4-aa83-4c1a36a4b177  Vault OSS
	//
	// b2c13ec1-60e8-4733-9a76-88dbb2ce2471  Vault Ent
	// ossVersionStr:=fmt.Sprintf("Vault/ (+https://www.vaultproject.io/; go1.16; %s)",ossVaultGUID)
	// entVersionStr:=fmt.Sprintf("Vault/ (+https://www.vaultproject.io/; go1.16; %s)",entVaultGUID)

	// old way of generating version
	pluginVersion := os.Getenv(pluginutil.PluginVaultVersionEnv)
	projectURL := "https://www.vaultproject.io/"
	rt := runtime.Version()
	ossVersionStr := fmt.Sprintf("Vault/%s (+%s; %s; %s)", pluginVersion, projectURL, rt, ossVaultGUID)
	entVersionStr := fmt.Sprintf("Vault/%s (+%s; %s; %s)", pluginVersion, projectURL, rt, entVaultGUID)

	testCases := map[string]struct {
		meta     string
		expected string
	}{
		"none": {
			meta:     "",
			expected: ossVersionStr,
		},
		"dev": {
			meta:     "dev",
			expected: ossVersionStr,
		},
		"ent": {
			meta:     "ent",
			expected: entVersionStr,
		},
		"prem": {
			meta:     "prem.hsm",
			expected: entVersionStr,
		},
		"unknown": {
			meta:     "glhf",
			expected: entVersionStr,
		},
	}

	for n, tc := range testCases {
		t.Run(n, func(t *testing.T) {
			version.VersionMetadata = tc.meta
			userAgentStr := userAgent()
			q.Q(userAgentStr)
			if userAgentStr != tc.expected {
				t.Fatalf("expected userAgent string to contain (%s), got: %s", tc.expected, userAgentStr)
			}
		})
	}
}
