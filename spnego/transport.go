package spnego

import (
	"net/http"
)

// Transport extends the native http.Transport to provide SPNEGO communication
type Transport struct {
	http.Transport
	spnego     Provider
	Username   string
	Password   string
	Domain     string
	KDC        []string
	KRB5Config string
}

// Error is used to distinguish errors from underlying libraries (gokrb5 or sspi).
type Error struct {
	Err error
}

// Error implements the error interface
func (e *Error) Error() string {
	return e.Err.Error()
}

// RoundTrip implements the RoundTripper interface.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.spnego == nil {
		t.spnego = New(&Options{
			Username:   t.Username,
			Password:   t.Password,
			Domain:     t.Domain,
			KDC:        t.KDC,
			KRB5Config: t.KRB5Config,
		})
	}

	if err := t.spnego.SetSPNEGOHeader(req); err != nil {
		return nil, &Error{Err: err}
	}

	rsp, err := t.Transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	return rsp, err
	// ToDo: process negotiate token from response
}
