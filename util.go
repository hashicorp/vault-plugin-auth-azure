package azureauth

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/helper/useragent"
)

// Using the same time parsing logic from https://github.com/coreos/go-oidc
// This code is licensed under the Apache 2.0 license
type jsonTime time.Time

func (j *jsonTime) UnmarshalJSON(b []byte) error {
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	var unix int64

	if t, err := n.Int64(); err == nil {
		unix = t
	} else {
		f, err := n.Float64()
		if err != nil {
			return err
		}
		unix = int64(f)
	}
	*j = jsonTime(time.Unix(unix, 0))
	return nil
}

// strListContains does a case-insensitive search of the string
// list for the value
func strListContains(haystack []string, needle string) bool {
	for _, item := range haystack {
		if strings.EqualFold(item, needle) {
			return true
		}
	}
	return false
}

// userAgent determines the User Agent to send on HTTP requests. This is mostly copied
// from the useragent helper in vault and may get replaced with something more general
// for plugins
func userAgent() string {
	ua := useragent.String()

	return ua
}
