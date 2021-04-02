package spnego

import (
	"bytes"
	"errors"
	"net"
	"net/http"
	"strings"
	"text/template"
)

// Krb5Conf config template data
type Krb5Conf struct {
	Domain string
	Kdcs   []string
}

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

	funcMap := template.FuncMap{
		"upper": strings.ToUpper,
	}

	tmpl := `[libdefaults]
	default_realm = {{.Domain | upper}}
[realms]
	{{.Domain | upper}} = {
		{{- range $kdc := .Kdcs}}
		kdc = {{$kdc}}{{end}}
	}
[domain_realm]
	.{{.Domain}} = {{.Domain | upper}}
	{{.Domain}} = {{.Domain | upper}}
`
	conf := &Krb5Conf{
		Domain: domain,
		Kdcs:   kdcs,
	}

	w := new(bytes.Buffer)
	tpl := template.Must(template.New("main").Funcs(funcMap).Parse(tmpl))
	tpl.Execute(w, conf)
	return w.String(), nil
}
