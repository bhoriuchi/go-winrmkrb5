// +build windows

package spnego

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/alexbrainman/sspi/negotiate"
)

// SSPI implements spnego.Provider interface on Windows OS
type sspi struct{}

// New constructs OS specific implementation of spnego.Provider interface
func New(opts *Options) Provider {
	return &sspi{}
}

// SetSPNEGOHeader puts the SPNEGO authorization header on HTTP request object
func (s *sspi) SetSPNEGOHeader(req *http.Request) error {
	h := strings.TrimRight(req.URL.Hostname(), ".")
	spn := "HTTP/" + h

	cred, err := negotiate.AcquireCurrentUserCredentials()
	if err != nil {
		return err
	}
	defer cred.Release()

	secctx, token, err := negotiate.NewClientContext(cred, spn)
	if err != nil {
		return err
	}
	defer secctx.Release()

	req.Header.Set("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(token))
	return nil
}
