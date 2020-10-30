package sidecar

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/csv"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"strings"
	"sync/atomic"

	"github.com/spiffe/go-spiffe/v2/logger"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	certsFileMode = os.FileMode(0644)
	keyFileMode   = os.FileMode(0600)
)

// Config contains config variables when creating a SPIFFE Sidecar.
type Config struct {
	AddIntermediatesToBundle bool   `hcl:"addIntermediatesToBundle"`
	AgentAddress             string `hcl:"agentAddress"`
	Cmd                      string `hcl:"cmd"`
	CmdArgs                  string `hcl:"cmdArgs"`
	CertDir                  string `hcl:"certDir"`
	MutatingWebhookName      string `hcl:"mutatingWebhookName"`
	SvidFileName             string `hcl:"svidFileName"`
	SvidKeyFileName          string `hcl:"svidKeyFileName"`
	SvidBundleFileName       string `hcl:"svidBundleFileName"`
	RenewSignal              string `hcl:"renewSignal"`
	Timeout                  string `hcl:"timeout"`
	ValidatingWebhookName    string `hcl:"validatingWebhookName"`
	KubeConfigFilePath       string `hcl:"kubeConfigFilePath"`
	Ctx                      context.Context
	ReloadExternalProcess    func() error
	Log                      logger.Logger
}

// Sidecar is the component that consumes the Workload API and renews certs
// implements the interface Sidecar
type Sidecar struct {
	client                       *kubernetes.Clientset
	config                       *Config
	processRunning               int32
	process                      *os.Process
	certReadyChan                chan struct{}
	ErrChan                      chan error
	mutatingWebhookCertificate   []byte
	validatingWebhookCertificate []byte
}

// NewSidecar creates a new SPIFFE sidecar
func NewSidecar(config *Config) (*Sidecar, error) {
	if config.Log == nil {
		config.Log = logger.Null
	}
	client, err := newKubeClient(config.KubeConfigFilePath)
	if err != nil {
		return nil, err
	}
	return &Sidecar{
		certReadyChan: make(chan struct{}),
		client:        client,
		config:        config,
		ErrChan:       make(chan error, 1),
	}, nil
}

// GetTimeout parses a time.Duration from the the Config,
// if there's an error during parsing, maybe because
// it's not well defined or not defined at all in the
// config, returns the defaultTimeout constant
func GetTimeout(config *Config) (time.Duration, error) {
	if config.Timeout == "" {
		return defaultTimeout, nil
	}

	t, err := time.ParseDuration(config.Timeout)
	if err != nil {
		return 0, err
	}
	return t, nil
}

// RunDaemon starts the main loop
// Starts the workload API client to listen for new SVID updates
// When a new SVID is received on the updateChan, the SVID certificates
// are stored in disk and a restart signal is sent to the proxy's process
func (s *Sidecar) RunDaemon() error {
	client, err := workloadapi.New(s.config.Ctx, workloadapi.WithAddr("unix://"+s.config.AgentAddress),
		workloadapi.WithLogger(s.config.Log))
	if err != nil {
		return fmt.Errorf("unable to create new workloadapi client: %v", err)
	}
	go func() {
		defer client.Close()
		err := client.WatchX509Context(s.config.Ctx, &x509Watcher{s})
		if err != nil && status.Code(err) != codes.Canceled {
			s.ErrChan <- err
		}
	}()

	return nil
}

// Updates the certificates stored in disk and signal the Process to restart
func (s *Sidecar) updateCertificates(svidResponse *workloadapi.X509Context) {
	s.config.Log.Infof("Updating certificates")

	err := s.dumpBundles(svidResponse)
	if err != nil {
		s.config.Log.Errorf("unable to dump bundle: %v", err)
		return
	}
	err = s.signalProcess()
	if err != nil {
		s.config.Log.Errorf("unable to signal process: %v", err)
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
	if s.config.Cmd != "" {
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
	}

	if s.config.ReloadExternalProcess != nil {
		err = s.config.ReloadExternalProcess()
		if err != nil {
			return fmt.Errorf("error reloading external process: %v", err)
		}
	}

	return nil
}

func (s *Sidecar) checkProcessExit() {
	atomic.StoreInt32(&s.processRunning, 1)
	_, err := s.process.Wait()
	if err != nil {
		s.config.Log.Errorf("error waiting for process exit: %v", err)
	}

	atomic.StoreInt32(&s.processRunning, 0)
}

// dumpBundles takes a X509SVIDResponse, representing a svid message from
// the Workload API, and calls writeCerts and writeKey to write to disk
// the svid, key and bundle of certificates.
// It is possible to change output setting `addIntermediatesToBundle` as true.
func (s *Sidecar) dumpBundles(svidResponse *workloadapi.X509Context) error {
	// There may be more than one certificate, but we are interested in the first one only
	svid := svidResponse.DefaultSVID()

	svidFile := path.Join(s.config.CertDir, s.config.SvidFileName)
	svidKeyFile := path.Join(s.config.CertDir, s.config.SvidKeyFileName)
	svidBundleFile := path.Join(s.config.CertDir, s.config.SvidBundleFileName)

	certs := svid.Certificates
	bundleSet, found := svidResponse.Bundles.Get(svid.ID.TrustDomain())
	if !found {
		return fmt.Errorf("no bundles found")
	}
	bundles := bundleSet.X509Authorities()
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

	if err := s.writeBundle(svidBundleFile, bundles); err != nil {
		return err
	}

	return nil
}

// writeBundle takes an array of certificates,
// and encodes them as PEM blocks, writing them to file
func (s *Sidecar) writeBundle(file string, certs []*x509.Certificate) error {
	pemData := make([]byte, 0, len(certs))
	for _, cert := range certs {
		b := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		pemData = append(pemData, pem.EncodeToMemory(b)...)
	}

	// Rotate cabundle field of ValidatingWebhookConfiguration
	if s.config.ValidatingWebhookName != "" && !bytes.Equal(s.validatingWebhookCertificate, pemData) {
		s.config.Log.Infof("Updating ValidatingWebhookConfiguration \"%s\" CABundle", s.config.ValidatingWebhookName)
		validatingWebhookConfiguration, err := s.client.AdmissionregistrationV1beta1().ValidatingWebhookConfigurations().Get(s.config.Ctx, s.config.ValidatingWebhookName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		for i := range validatingWebhookConfiguration.Webhooks {
			validatingWebhookConfiguration.Webhooks[i].ClientConfig.CABundle = pemData
		}
		_, err = s.client.AdmissionregistrationV1beta1().ValidatingWebhookConfigurations().Update(s.config.Ctx, validatingWebhookConfiguration, metav1.UpdateOptions{})
		if err != nil {
			return err
		}
		s.validatingWebhookCertificate = pemData
	}

	// Rotate cabundle field of MutatingWebhookConfiguration
	if s.config.MutatingWebhookName != "" && !bytes.Equal(s.mutatingWebhookCertificate, pemData) {
		s.config.Log.Infof("Updating MutatingWebhookConfiguration \"%s\" CABundle", s.config.MutatingWebhookName)
		mutatingWebhookConfiguration, err := s.client.AdmissionregistrationV1beta1().MutatingWebhookConfigurations().Get(s.config.Ctx, s.config.MutatingWebhookName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		for i := range mutatingWebhookConfiguration.Webhooks {
			mutatingWebhookConfiguration.Webhooks[i].ClientConfig.CABundle = pemData
		}
		_, err = s.client.AdmissionregistrationV1beta1().MutatingWebhookConfigurations().Update(s.config.Ctx, mutatingWebhookConfiguration, metav1.UpdateOptions{})
		if err != nil {
			return err
		}
		s.mutatingWebhookCertificate = pemData
	}

	return ioutil.WriteFile(file, pemData, certsFileMode)
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

// x509Watcher is a sample implementation of the workload.X509SVIDWatcher interface
type x509Watcher struct {
	sidecar *Sidecar
}

// OnX509ContextUpdate is run every time an SVID is updated
func (w x509Watcher) OnX509ContextUpdate(svids *workloadapi.X509Context) {
	for _, svid := range svids.SVIDs {
		w.sidecar.config.Log.Infof("SVID updated for spiffeID: %q", svid.ID)
	}

	w.sidecar.updateCertificates(svids)
}

// OnX509ContextWatchError is run when the client runs into an error
func (w x509Watcher) OnX509ContextWatchError(err error) {
	if status.Code(err) != codes.Canceled {
		w.sidecar.config.Log.Infof("Watching x509 context: %v", err)
	}
}

func newKubeClient(configPath string) (*kubernetes.Clientset, error) {
	config, err := getKubeConfig(configPath)
	if err != nil {
		return nil, err
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func getKubeConfig(configPath string) (*rest.Config, error) {
	if configPath != "" {
		return clientcmd.BuildConfigFromFlags("", configPath)
	}
	return rest.InClusterConfig()
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
