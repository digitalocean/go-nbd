// SPDX-License-Identifier: Apache-2.0

package nbd

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

const megabyte uint64 = 1024 * 1024

var nbdkitBin = func(defaultValue string) string {
	if v := os.Getenv("NBDKIT"); v != "" {
		return v
	}
	return defaultValue
}("nbdkit")

func provideNBD(
	t *testing.T,
	pidfile string,
	size uint64,
	port int,
) (wait func(), err error) {
	return nbdkitTCP(t, pidfile, size, port)
}

func provideSecureNBD(
	t *testing.T,
	pidfile string,
	size uint64,
	port int,
	pkiDir string,
) (tlsConf *tls.Config, wait func(), err error) {
	wait = func() {}

	ca, capriv, err := newTestCACertAndKey()
	if err != nil {
		return nil, wait, err
	}

	caCert, err := x509.ParseCertificate(ca)
	if err != nil {
		return nil, wait, fmt.Errorf("parse CA certificate: %w", err)
	}

	server, serverpriv, err := newServerCertAndKey(caCert, capriv)
	if err != nil {
		return nil, wait, err
	}

	err = nbdkitWritePKI(pkiDir, ca, server, serverpriv)
	if err != nil {
		return nil, wait, err
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(caCert)

	tlsConf = &tls.Config{
		RootCAs:            certPool,
		InsecureSkipVerify: true,
	}

	extra := []string{
		"--tls=require",
		"--tls-certificates",
		pkiDir,
	}

	wait, err = nbdkitTCP(t, pidfile, size, port, extra...)
	if err != nil {
		return nil, wait, err
	}

	return tlsConf, wait, nil
}

func nbdkitTCP(
	t *testing.T,
	pidfile string,
	size uint64,
	port int,
	extra ...string,
) (wait func(), err error) {
	args := []string{
		"--exit-with-parent",
		"--pidfile",
		pidfile,
		"--port",
		strconv.FormatInt(int64(port), 10),
		"memory",
		fmt.Sprintf("%dM", size/megabyte),
	}

	wait, err = nbdkit(t, append(extra, args...))
	if err != nil {
		return wait, err
	}

	// The --pidfile option has nbdkit write a file when it
	// is ready to accept connections, so we can spin on this
	// similar to the Unix domain socket tests to avoid trying
	// to talk to nbdkit before it is ready.

	for {
		_, err := os.Stat(pidfile)
		if err == nil {
			break
		}
		if os.IsNotExist(err) {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		return wait, fmt.Errorf("waiting for pidfile: %w", err)
	}

	return wait, nil
}

func provideNBDUnix(t *testing.T, name string, size uint64) (wait func(), err error) {
	return nbdkitUnix(t, name, size)
}

func provideSecureNBDUnix(t *testing.T, name string, size uint64, pkiDir string) (tlsConf *tls.Config, wait func(), err error) {
	wait = func() {}

	ca, capriv, err := newTestCACertAndKey()
	if err != nil {
		return nil, wait, err
	}

	caCert, err := x509.ParseCertificate(ca)
	if err != nil {
		return nil, wait, fmt.Errorf("parse CA certificate: %w", err)
	}

	server, serverpriv, err := newServerCertAndKey(caCert, capriv)
	if err != nil {
		return nil, wait, err
	}

	err = nbdkitWritePKI(pkiDir, ca, server, serverpriv)
	if err != nil {
		return nil, wait, err
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(caCert)

	tlsConf = &tls.Config{
		RootCAs:            certPool,
		InsecureSkipVerify: true,
	}

	extra := []string{
		"--tls=require",
		"--tls-certificates",
		pkiDir,
	}

	wait, err = nbdkitUnix(t, name, size, extra...)
	if err != nil {
		return nil, wait, err
	}

	return tlsConf, wait, nil
}

func nbdkitUnix(t *testing.T, name string, size uint64, extra ...string) (wait func(), err error) {
	args := []string{
		"--exit-with-parent",
		"-U",
		name,
		"memory",
		fmt.Sprintf("%dM", size/megabyte),
	}

	wait, err = nbdkit(t, append(extra, args...))
	if err != nil {
		return wait, err
	}

	for {
		_, err := os.Stat(name)
		if err == nil {
			break
		}
		if os.IsNotExist(err) {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		return wait, fmt.Errorf("waiting for Unix socket: %w", err)
	}

	return wait, nil
}

func nbdkit(t *testing.T, args []string) (wait func(), err error) {
	wait = func() {}

	ctx, cancel := context.WithCancel(context.Background())
	_ = cancel // Just to appease the 'lostcancel' lint failure

	t.Logf("%v", append([]string{nbdkitBin}, args...))
	cmd := exec.CommandContext(ctx, nbdkitBin, args...)

	err = cmd.Start()
	if err != nil {
		return wait, fmt.Errorf("start nbdkit %v: %w", args, err)
	}

	wait = func() {
		cancel()
		err = cmd.Wait()
		t.Log("stdout", cmd.Stdout)
		t.Log("stderr", cmd.Stderr)
	}

	return wait, nil
}

func nbdkitWritePKI(
	dir string,
	caDER []byte,
	serverDER []byte,
	privkey *rsa.PrivateKey,
) error {
	// from man page: nbdkit-tls(1), these are the expected
	// filenames under the directory given to nbdkit via
	// --tls-certificates.
	blocks := map[string]*pem.Block{
		"ca-cert.pem": {
			Type:  "CERTIFICATE",
			Bytes: caDER,
		},
		"server-cert.pem": {
			Type:  "CERTIFICATE",
			Bytes: serverDER,
		},
		"server-key.pem": {
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privkey),
		},
	}

	for filename, block := range blocks {
		f, err := os.Create(filepath.Join(dir, filename))
		if err != nil {
			return fmt.Errorf("create %s: %w", filename, err)
		}
		defer func() { _ = f.Close() }()

		err = pem.Encode(f, block)
		if err != nil {
			return fmt.Errorf("write PEM block to %s: %v", filename, err)
		}
	}

	return nil
}
