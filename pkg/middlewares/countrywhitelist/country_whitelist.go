package countrywhitelist

import (
	"context"
	"encoding/binary"
	"fmt"
	"github.com/opentracing/opentracing-go/ext"
	"github.com/oschwald/maxminddb-golang"
	"github.com/traefik/traefik/v2/pkg/config/dynamic"
	"github.com/traefik/traefik/v2/pkg/log"
	"github.com/traefik/traefik/v2/pkg/middlewares"
	"github.com/traefik/traefik/v2/pkg/tracing"
	net2 "net"
	"net/http"
	"os"
	"strings"
)

const (
	typeName                   = "CountryWhitelist"
	envVarGeoIPCountriesDBPath = "GEOIP_DB_PATH"
)

// countryWhitelist is a middleware used to set countries whitelist
type countryWhitelist struct {
	next http.Handler
	name string

	defaultAllow bool
	countries    map[string]bool
	ranges       []ipRange
	db           *maxminddb.Reader
}

// New creates a new handler.
func New(ctx context.Context, next http.Handler, config dynamic.CountryWhitelist, name string) (http.Handler, error) {
	log.FromContext(middlewares.GetLoggerCtx(ctx, name, typeName)).Debug("Creating middleware")
	res := &countryWhitelist{
		next: next,
		name: name,
	}

	return res, res.load(config)
}

func (c *countryWhitelist) GetTracingInformation() (string, ext.SpanKindEnum) {
	return c.name, tracing.SpanKindNoneEnum
}

func (c *countryWhitelist) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	ctx := middlewares.GetLoggerCtx(r.Context(), c.name, typeName)
	logger := log.FromContext(ctx)
	// Get remote IP
	ip, _, err := net2.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}

	allowed, match, err := c.isAllowed(ip)
	logger.Debugf("Calculated effect for %s: allowed: %t, matched by rule: %s, err: %v", ip, allowed, match, err)

	if err != nil {
		// Fallback to default behavior
		if c.defaultAllow {
			c.next.ServeHTTP(rw, r)
			return
		}
		tracing.SetErrorWithEvent(r, "IP is forbidden")
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	if !allowed {
		tracing.SetErrorWithEvent(r, "IP is forbidden")
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	c.next.ServeHTTP(rw, r)
}

func (c *countryWhitelist) load(config dynamic.CountryWhitelist) error {
	dbPath := "./GeoLite2-Country.mmdb"
	if path := os.Getenv(envVarGeoIPCountriesDBPath); path != "" {
		dbPath = path
	}
	db, err := maxminddb.Open(dbPath)
	if err != nil {
		return err
	}
	c.db = db
	c.defaultAllow = config.DefaultAllow

	addCountries := func(countries []string, allowed bool) {
		for _, code := range countries {
			c.countries[strings.ToLower(code)] = allowed
		}
	}
	c.countries = make(map[string]bool)
	addCountries(config.AllowedCountries, true)
	addCountries(config.DeniedCountries, false)

	addRanges := func(ranges []string, allowed bool) error {
		for _, r := range ranges {
			if r == "" {
				continue
			}
			_, net, err := net2.ParseCIDR(r)
			if err != nil {
				return fmt.Errorf("range is invalid: %s, %v", r, err)
			}
			c.ranges = append(c.ranges, ipRange{
				allowed: allowed,
				ipnet:   net,
			})
		}
		return nil
	}
	if err := addRanges(config.AllowedRanges, true); err != nil {
		return err
	}
	return addRanges(config.DeniedRanges, false)
}

// isAllowed returns the effect for the incoming request IP and the matching policy rule
func (c *countryWhitelist) isAllowed(srcIP string) (bool, string, error) {
	// Parse IP string
	ip := net2.ParseIP(srcIP)
	if ip == nil {
		return false, "", fmt.Errorf("failed to parse IP: %s", srcIP)
	}

	// Lookup by ip range
	for _, r := range c.ranges {
		if r.ipnet.Contains(ip) {
			return r.allowed, r.ipnet.String(), nil
		}
	}

	// Lookup country from mmdb
	var res mmdbRecord
	if err := c.db.Lookup(ip, &res); err != nil {
		return false, "", err
	}

	// If IP originating country is found, enforce policy
	if res.Country.ISOCode != "" {
		if allowed, found := c.countries[strings.ToLower(res.Country.ISOCode)]; found {
			return allowed, res.Country.ISOCode, nil
		}
	}

	if privateIP(ip) {
		// Always accept internal IP ranges
		return true, "internal IP", nil
	}

	return c.defaultAllow, "default rule", nil
}

// privateIP returns true if the given ip belongs to the private address space
func privateIP(ipnet net2.IP) bool {
	var ip uint32
	if len(ipnet) == 16 {
		ip = binary.BigEndian.Uint32(ipnet[12:16])
	} else {
		ip = binary.BigEndian.Uint32(ipnet)
	}

	return (ip >= 150994944 && ip <= 167772159) || // 9.0.0.0/8 Used as private network by DC/OS
		(ip >= 2130706432 && ip <= 2147483647) || // 127.0.0.0/8
		(ip >= 1681915904 && ip <= 1686110207) || // 100.64.0.0–100.127.255.255
		(ip >= 3232235520 && ip <= 3232301055) || // 192.168/16
		(ip >= 2886729728 && ip <= 2887778303) || // 172.16/12
		(ip >= 167772160 && ip <= 184549375) || // 10.0.0.0/8
		(ip >= 3221225472 && ip <= 3221225727) || // 192.0.0.0-192.0.0.255 (192.0.0.0/24) range
		(ip >= 3221225984 && ip <= 3221226239) || // 192.0.2.0-192.0.2.255 (192.0.2.0/24) range
		(ip >= 3325256704 && ip <= 3325256959) || // 198.51.100.0-198.51.100.255 (198.51.100.0/24) range
		(ip >= 2851995648 && ip <= 2852061183) || // 169.254/16
		(ip >= 3323068416 && ip <= 3323199487) || // 198.18.0.0-198.19.255.255 (198.18.0.0/15) range
		(ip >= 3227017984 && ip <= 3227018239) || // 192.88.99.0-192.88.99.255 (192.88.99.0/24) range
		(ip >= 3405803776 && ip <= 3405804031) || // 203.0.113.0-203.0.113.255 (203.0.113.0/24) range
		(ip >= 4026531840 && ip <= 4294967295) // 240.0.0.0-255.255.255.255  (240.0.0.0/4) range
}

// See: https://github.com/maxmind/mmdbinspect#examples
type mmdbRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	Continent struct {
		Code string `maxminddb:"code"`
	} `maxminddb:"continent"`
}

type ipRange struct {
	ipnet   *net2.IPNet
	allowed bool
}
