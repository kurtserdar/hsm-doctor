package inventory

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// ParseCABundle reads PEM-encoded certificates (a trust bundle) into x509
// certificates for use as chain-validation trust anchors.
func ParseCABundle(pemData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing CA bundle: %w", err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("CA bundle contains no certificates")
	}
	return certs, nil
}

// ValidateChains verifies each certificate on the token against the supplied
// trust anchors (roots), using other token certificates and the bundle as
// intermediates. It records the outcome in each CertInfo.ChainStatus. With no
// roots it is a no-op: without a trust context, a leaf whose issuer simply
// lives elsewhere is not "broken".
func ValidateChains(inv *Inventory, roots []*x509.Certificate) {
	if inv == nil || len(roots) == 0 {
		return
	}

	rootPool := x509.NewCertPool()
	interPool := x509.NewCertPool()
	for _, r := range roots {
		rootPool.AddCert(r)
		interPool.AddCert(r)
	}

	// Token CA certificates serve as intermediates for chain building.
	type parsed struct {
		obj  *Object
		cert *x509.Certificate
	}
	var all []parsed
	for i := range inv.Objects {
		o := &inv.Objects[i]
		if o.Class != ClassCertificate || o.Certificate == nil || len(o.Certificate.Raw) == 0 {
			continue
		}
		c, err := x509.ParseCertificate(o.Certificate.Raw)
		if err != nil {
			continue
		}
		if c.IsCA {
			interPool.AddCert(c)
		}
		all = append(all, parsed{obj: o, cert: c})
	}

	opts := x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: interPool,
		CurrentTime:   inv.ScannedAt,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	for _, p := range all {
		if _, err := p.cert.Verify(opts); err != nil {
			p.obj.Certificate.ChainStatus = "unverified: " + err.Error()
		} else {
			p.obj.Certificate.ChainStatus = "verified"
		}
	}
}
