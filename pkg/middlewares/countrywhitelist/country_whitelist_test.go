package countrywhitelist

import (
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v2/pkg/config/dynamic"
	"testing"
)

func TestAllowed(t *testing.T) {
	type testCase struct {
		policy    dynamic.CountryWhitelist
		scenarios map[string]bool
	}
	for _, tt := range []testCase{
		{
			policy: dynamic.CountryWhitelist{
				AllowedCountries: []string{"il", "us"},
				DeniedCountries:  []string{"de"},
				AllowedRanges:    []string{"40.0.0.0/24", "80.1.0.0/24"},
				DeniedRanges:     []string{"40.2.0.0/24"},
				DefaultAllow:     false,
			},
			scenarios: map[string]bool{
				"1.2.3.4":     false, // AU, match by default behavior
				"8.8.8.8":     true,  // US, match by allowed countries
				"5.6.7.8":     false, // DE, match by denied countries
				"40.0.0.1":    true,  // Match by allowed range
				"80.0.1.1":    false, // Match by default behavior
				"40.2.0.1":    false, // Match by denied range
				"192.168.1.2": true,  // Match by private addr
			},
		},
		{
			policy: dynamic.CountryWhitelist{
				AllowedCountries: []string{"il", "us"},
				DeniedCountries:  []string{"de"},
				AllowedRanges:    []string{"40.0.0.0/24", "40.1.0.0/24"},
				DeniedRanges:     []string{"40.2.0.0/24"},
				DefaultAllow:     true,
			},
			scenarios: map[string]bool{
				"1.2.3.4":  true,  // AU, match by default behavior
				"8.8.8.8":  true,  // US, match by allowed countries
				"5.6.7.8":  false, // DE, match by denied countries
				"40.0.0.1": true,  // Match by allowed range
				"40.2.0.1": false, // Match by denied range
				"40.3.0.1": true,  // Match by default behavior
			},
		},
	} {
		t.Logf("Default allow: %t", tt.policy.DefaultAllow)
		var c countryWhitelist
		require.NoError(t, c.load(tt.policy))
		for ip, allowed := range tt.scenarios {
			t.Logf("Testing %s, allowed: %t", ip, allowed)
			verdictAllowed, _, err := c.isAllowed(ip)
			require.NoError(t, err)
			require.Equal(t, allowed, verdictAllowed)
		}
	}
}
