// +build !windows

package spnego

import (
	"net/http"
	"os"
	"os/user"
	"strings"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

type krb5 struct {
	cfg  *config.Config
	cl   *client.Client
	opts *Options
}

// New constructs OS specific implementation of spnego.Provider interface
func New(opts *Options) Provider {
	if opts == nil {
		opts = &Options{}
	}

	return &krb5{opts: opts}
}

func (k *krb5) makeCfg() error {
	var err error

	if k.cfg != nil {
		return nil
	}

	// if krb5 not specified but kdcs and domain are, generate the krb5.conf
	if len(k.opts.KRB5Config) == 0 && k.opts.KDC != nil && len(k.opts.KDC) > 0 && len(k.opts.Domain) > 0 {
		if k.opts.KRB5Config, err = GenerateKRB5Conf(k.opts.Domain, k.opts.KDC); err != nil {
			return err
		}
	}

	// if the krb5conf was specified, generate a config from the string
	if len(k.opts.KRB5Config) > 0 {
		if k.cfg, err = config.NewFromString(k.opts.KRB5Config); err != nil {
			return err
		}
	} else {
		cfgPath := os.Getenv("KRB5_CONFIG")
		if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
			cfgPath = "/etc/krb5.conf" // ToDo: Macs and Windows have different path, also some Unix may have /etc/krb5/krb5.conf
		}

		if k.cfg, err = config.Load(cfgPath); err != nil {
			return err
		}
	}

	return nil
}

func (k *krb5) makeClient() error {
	if k.cl != nil {
		return nil
	}

	// if a username, password, and domain were provided create a client with password
	if len(k.opts.Username) > 0 && len(k.opts.Password) > 0 && len(k.opts.Domain) > 0 {
		k.cl = client.NewWithPassword(
			k.opts.Username,
			strings.ToUpper(k.opts.Domain),
			k.opts.Password,
			k.cfg,
			client.DisablePAFXFAST(true),
		)

		return nil
	}

	// otherwise try local krb5 cache
	u, err := user.Current()
	if err != nil {
		return err
	}

	ccpath := "/tmp/krb5cc_" + u.Uid

	ccname := os.Getenv("KRB5CCNAME")
	if strings.HasPrefix(ccname, "FILE:") {
		ccpath = strings.SplitN(ccname, ":", 2)[1]
	}

	ccache, err := credentials.LoadCCache(ccpath)
	if err != nil {
		return err
	}
	cl, err := client.NewFromCCache(ccache, k.cfg, client.DisablePAFXFAST(true))
	if err != nil {
		return err
	}

	k.cl = cl
	return nil
}

func (k *krb5) SetSPNEGOHeader(req *http.Request) error {
	h := strings.TrimRight(req.URL.Hostname(), ".")

	if err := k.makeCfg(); err != nil {
		return err
	}

	if err := k.makeClient(); err != nil {
		return err
	}

	return spnego.SetSPNEGOHeader(k.cl, req, "HTTP/"+h)
}
