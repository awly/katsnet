package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"tailscale.com/client/tailscale"
	"tailscale.com/tsnet"
)

const (
	caCertPath         = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	kubeAPIAddr        = "https://kubernetes.default"
	defaultSATokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

func main() {
	hostname := os.Getenv("TS_HOSTNAME")
	if hostname == "" {
		log.Fatal("missing the TS_HOSTNAME env var")
	}
	// Allow a custom state directory, for use with persistent volume mounts.
	stateDir := os.Getenv("TS_STATE")
	// Allow SA token override in case projected tokens are used.
	//
	// Note: we cannot project the token into the defaultSATokenPath because
	// that would make the CA cert in the same directory inaccessible.
	saTokenPath := os.Getenv("KUBERNETES_SERVICEACCOUNT_TOKEN_PATH")
	if saTokenPath == "" {
		saTokenPath = defaultSATokenPath
	}

	s := &tsnet.Server{
		Hostname: hostname,
		Dir:      stateDir,
	}
	ln, err := s.Listen("tcp", ":80")
	if err != nil {
		log.Fatal(err)
	}
	// Best-effort graceful shutdown.
	sigc := make(chan os.Signal, 1)
	go func() {
		<-sigc
		ln.Close()
		s.Close()
		os.Exit(0)
	}()
	signal.Notify(sigc, syscall.SIGTERM)

	tc, err := s.LocalClient()
	if err != nil {
		log.Fatal(err)
	}
	rp, err := newKubeAPIReverseProxy()
	if err != nil {
		log.Fatal(err)
	}
	p := proxy{
		tc:          tc,
		forward:     rp,
		saTokenPath: saTokenPath,
	}

	// TODO: metrics and debug endpoints.
	http.HandleFunc("/", p.serveAPI)
	log.Fatal(http.Serve(ln, nil))
}

type proxy struct {
	tc          *tailscale.LocalClient
	forward     http.Handler
	saTokenPath string
}

// serveAPI serves the kube-apiserver endpoints through this proxy.
func (p proxy) serveAPI(rw http.ResponseWriter, r *http.Request) {
	// Get user identity and populate impersonation headers.
	who, err := p.tc.WhoIs(r.Context(), r.RemoteAddr)
	if err != nil {
		log.Println("failed to get client user identity for %q: %v", r.RemoteAddr, err)
		http.Error(rw, "could not get your tailnet user identity", http.StatusUnauthorized)
		return
	}
	r.Header.Set("Impersonate-User", who.UserProfile.LoginName)

	// Get k8s SA token and add it for authorization.
	// TODO: if this becomes a bottleneck, cache the loaded token.
	kubeAPIToken, err := os.ReadFile(p.saTokenPath)
	if err != nil {
		log.Println("failed to load service account token: %v", err)
		http.Error(rw, "katsnet proxy could not authenticate to the kubernetes API", http.StatusInternalServerError)
		return
	}
	r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", kubeAPIToken))

	p.forward.ServeHTTP(rw, r)
}

// newKubeAPIReverseProxy creates a ReverseProxy for kube-apiserver within the
// current cluster.
func newKubeAPIReverseProxy() (*httputil.ReverseProxy, error) {
	kubeAPICACert, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert from %q: %w", caCertPath, err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(kubeAPICACert) {
		return nil, fmt.Errorf("failed to parse CA certificate from %q", caCertPath)
	}
	kubeAPI, err := url.Parse(kubeAPIAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse k8s API address %q: %w", kubeAPIAddr, err)
	}
	return &httputil.ReverseProxy{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caPool,
			},
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		Rewrite: func(r *httputil.ProxyRequest) { r.SetURL(kubeAPI) },
	}, nil
}
