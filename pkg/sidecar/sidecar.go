package sidecar

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/csv"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"
	"strings"
	"sync/atomic"
	"time"

	"github.com/spiffe/go-spiffe/workload"
	"golang.org/x/sys/unix"
)

// Config contains config variables when creating a SPIFFE Sidecar.
type Config struct {
	AgentAddress string `hcl:"agentAddress"`
	Cmd          string `hcl:"cmd"`
	CmdArgs      string `hcl:"cmdArgs"`
	CertDir      string `hcl:"certDir"`
	// Merge intermediate certificates into Bundle file instead of SVID file,
	// it is useful is some scenarios like MySQL,
	// where this is the expected format for presented certificates and bundles
	AddIntermediatesToBundle bool   `hcl:"addIntermediatesToBundle"`
	SvidFileName             string `hcl:"svidFileName"`
	SvidKeyFileName          string `hcl:"svidKeyFileName"`
	SvidBundleFileName       string `hcl:"svidBundleFileName"`
	RenewSignal              string `hcl:"renewSignal"`
	Timeout                  string `hcl:"timeout"`
}

// Sidecar is the component that consumes the Workload API and renews certs
// implements the interface Sidecar
type Sidecar struct {
	config            *Config
	processRunning    int32
	process           *os.Process
	workloadAPIClient *workload.X509SVIDClient
	certReadyChan     chan struct{}
	ErrChan         chan error
}

const (
	// default timeout Duration for the workloadAPI client when the defaultTimeout
	// is not configured in the .conf file
	defaultTimeout = 5 * time.Second
	delayMin       = time.Second
	delayMax       = time.Minute

	certsFileMode = os.FileMode(0644)
	keyFileMode   = os.FileMode(0600)
)

// NewSidecar creates a new SPIFFE sidecar
func NewSidecar(config *Config) (*Sidecar, error) {
	sidecar := &Sidecar{
		config:        config,
		certReadyChan: make(chan struct{}),
		ErrChan:     make(chan error),
	}

	w := watcher{sidecar: sidecar}
	workloadAPIClient, err := workload.NewX509SVIDClient(w, workload.WithAddr("unix://"+config.AgentAddress))
	if err != nil {
		return nil, err
	}
	sidecar.workloadAPIClient = workloadAPIClient

	return sidecar, nil
}


// RunDaemon starts the main loop
// Starts the workload API client to listen for new SVID updates
// When a new SVID is received on the updateChan, the SVID certificates
// are stored in disk and a restart signal is sent to the proxy's process
func (s *Sidecar) RunDaemon(ctx context.Context) error {
	err := s.workloadAPIClient.Start()
	if err != nil {
		return err
	}

	return nil
}

// StopDaemon starts the main loop
func (s *Sidecar) StopDaemon(ctx context.Context) error {
	err := s.workloadAPIClient.Stop()
	if err != nil {
		return err
	}

	return nil
}

// watcher is a sample implementation of the workload.X509SVIDWatcher interface
type watcher struct{
	sidecar *Sidecar
}

// UpdateX509SVIDs is run every time an SVID is updated
func (w watcher) UpdateX509SVIDs(svids *workload.X509SVIDs) {
	for _, svid := range svids.SVIDs {
		log.Printf("SVID updated for spiffeID: %q", svid.SPIFFEID)
	}

	updateCertificates(w.sidecar, svids)
}

// OnError is run when the client runs into an error
func (w watcher) OnError(err error) {
	w.sidecar.ErrChan <- err
}


// Updates the certificates stored in disk and signal the Process to restart
func updateCertificates(s *Sidecar, svidResponse *workload.X509SVIDs) {
	log.Println("Updating certificates")

	err := s.dumpBundles(svidResponse)
	if err != nil {
		log.Printf("unable to dump bundle: %v", err)
		return
	}
	if s.config.Cmd != "" {
		err = s.signalProcess()
		if err != nil {
			log.Printf("unable to signal process: %v", err)
		}
	}

	select {
	case s.certReadyChan <- struct{}{}:
	default:
	}
}

// CertReadyChan returns a channel to know when the certificates are ready
func (s *Sidecar) CertReadyChan() <-chan struct{} {
	return s.certReadyChan
}

// signalProcess sends the configured Renew signal to the process running the proxy
// to reload itself so that the proxy uses the new SVID
func (s *Sidecar) signalProcess() (err error) {
	if atomic.LoadInt32(&s.processRunning) == 0 {
		cmdArgs, err := getCmdArgs(s.config.CmdArgs)
		if err != nil {
			return fmt.Errorf("error parsing cmd arguments: %v", err)
		}

		cmd := exec.Command(s.config.Cmd, cmdArgs...) // #nosec
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err = cmd.Start()
		if err != nil {
			return fmt.Errorf("error executing process: %v\n%v", s.config.Cmd, err)
		}
		s.process = cmd.Process
		go s.checkProcessExit()
	} else {
		// Signal to reload certs
		sig := unix.SignalNum(s.config.RenewSignal)
		if sig == 0 {
			return fmt.Errorf("error getting signal: %v", s.config.RenewSignal)
		}

		err = s.process.Signal(sig)
		if err != nil {
			return fmt.Errorf("error signaling process with signal: %v\n%v", sig, err)
		}
	}


	return nil
}

// getCmdArgs receives the command line arguments as a string
// and split it at spaces, except when the space is inside quotation marks
func getCmdArgs(args string) ([]string, error) {
	if args == "" {
		return []string{}, nil
	}

	r := csv.NewReader(strings.NewReader(args))
	r.Comma = ' ' // space
	cmdArgs, err := r.Read()
	if err != nil {
		return nil, err
	}

	return cmdArgs, nil
}

func (s *Sidecar) checkProcessExit() {
	atomic.StoreInt32(&s.processRunning, 1)
	_, err := s.process.Wait()
	if err != nil {
		log.Printf("error waiting for process exit: %v", err)
	}

	atomic.StoreInt32(&s.processRunning, 0)
}

// dumpBundles takes a X509SVIDResponse, representing a svid message from
// the Workload API, and calls writeCerts and writeKey to write to disk
// the svid, key and bundle of certificates.
// It is possible to change output setting `addIntermediatesToBundle` as true.
func (s *Sidecar) dumpBundles(svidResponse *workload.X509SVIDs) error {
	// There may be more than one certificate, but we are interested in the first one only
	svid := svidResponse.SVIDs[0]

	svidFile := path.Join(s.config.CertDir, s.config.SvidFileName)
	svidKeyFile := path.Join(s.config.CertDir, s.config.SvidKeyFileName)
	svidBundleFile := path.Join(s.config.CertDir, s.config.SvidBundleFileName)

	certs := svid.Certificates
	bundles := svid.TrustBundle
	privateKey := svid.PrivateKey.(crypto.PrivateKey)
	privateKeyBytes, _ := x509.MarshalPKCS8PrivateKey(privateKey)

	// Add intermediates into bundles, and remove them from certs
	if s.config.AddIntermediatesToBundle {
		bundles = append(bundles, certs[1:]...)
		certs = []*x509.Certificate{certs[0]}
	}

	if err := s.writeCerts(svidFile, certs); err != nil {
		return err
	}

	if err := s.writeKey(svidKeyFile, privateKeyBytes); err != nil {
		return err
	}

	if err := s.writeCerts(svidBundleFile, bundles); err != nil {
		return err
	}

	return nil
}

// writeCerts takes an array of certificates,
// and encodes them as PEM blocks, writing them to file
func (s *Sidecar) writeCerts(file string, certs []*x509.Certificate) error {
	pemData := make([]byte, 0, len(certs))
	for _, cert := range certs {
		b := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		pemData = append(pemData, pem.EncodeToMemory(b)...)
	}

	return ioutil.WriteFile(file, pemData, certsFileMode)
}

// writeKey takes a private key as a slice of bytes,
// formats as PEM, and writes it to file
func (s *Sidecar) writeKey(file string, data []byte) error {
	b := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: data,
	}

	return ioutil.WriteFile(file, pem.EncodeToMemory(b), keyFileMode)
}

// parses a time.Duration from the the Config,
// if there's an error during parsing, maybe because
// it's not well defined or not defined at all in the
// config, returns the defaultTimeout constant
func getTimeout(config *Config) (time.Duration, error) {
	if config.Timeout == "" {
		return defaultTimeout, nil
	}

	t, err := time.ParseDuration(config.Timeout)
	if err != nil {
		return 0, err
	}
	return t, nil
}
