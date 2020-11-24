package spnego

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// Provider is the interface that wraps OS agnostic functions for handling SPNEGO communication
type Provider interface {
	SetSPNEGOHeader(*http.Request) error
}

// Options options
type Options struct {
	Username   string
	Password   string
	Domain     string
	KDC        []string
	KRB5Config string
}

func canonicalizeHostname(hostname string) (string, error) {
	addrs, err := net.LookupHost(hostname)
	if err != nil {
		return "", err
	}
	if len(addrs) < 1 {
		return hostname, nil
	}

	names, err := net.LookupAddr(addrs[0])
	if err != nil {
		return "", err
	}
	if len(names) < 1 {
		return hostname, nil
	}

	return strings.TrimRight(names[0], "."), nil
}

// GenerateKRB5Conf a basic krb5.conf string
func GenerateKRB5Conf(domain string, kdcs []string) (string, error) {
	if len(domain) == 0 {
		return "", errors.New("no domain specified")
	}

	if len(kdcs) == 0 {
		return "", errors.New("no kdcs specified")
	}

	uDomain := strings.ToUpper(domain)
	lDomain := strings.ToLower(domain)

	kdcArray := []string{}
	for _, kdc := range kdcs {
		if len(kdc) == 0 {
			return "", errors.New("empty string specified for kdc")
		}

		kdcArray = append(kdcArray, fmt.Sprintf("  kdc = %s", kdc))
	}

	conf := fmt.Sprintf(`[libdefaults]
	default_realm = %s
	[realms]
	%s = {
%s
	default_domain = %s
}`, uDomain, uDomain, strings.Join(kdcArray, "\n"), lDomain)

	return conf, nil
}
