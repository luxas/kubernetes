/*
Copyright 2024 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package conditionalauthz

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"testing"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	apiservertesting "k8s.io/kubernetes/cmd/kube-apiserver/app/testing"
	"k8s.io/kubernetes/test/integration/framework"
)

func setupTestServer(t *testing.T) {

	// Generate a private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	// Create certificate template
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Company"},
			CommonName:   "localhost",
		},
		DNSNames:              []string{"localhost"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create certificate using the template and private key
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	certBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	webhookConfig := `
apiVersion: v1
# kind of the API object
kind: Config
# clusters refers to the remote service.
clusters:
- name: authz-webhook
  cluster:
    # CA for verifying the remote service.
    certificate-authority-data: ` + base64.StdEncoding.EncodeToString(certBytes) + `
    # URL of remote service to query. Must use 'https'. May not include parameters.
    server: https://localhost:4321/authorize

# users refers to the API Server's webhook configuration.
users:
  - name: kube-apiserver
    user:
      token: abce

# kubeconfig files require a context. Provide one for the API Server.
current-context: authz-webhook
contexts:
- context:
    cluster: authz-webhook
    user: kube-apiserver
  name: authz-webhook
`

	webhookConfigFile := "/tmp/webhook-config.yaml"
	if err := os.WriteFile(webhookConfigFile, []byte(webhookConfig), 0644); err != nil {
		log.Fatalf("Failed to write webhook config file: %v", err)
	}

	// Set up the HTTPS server
	cert, err := tls.X509KeyPair(
		certBytes,
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}),
	)
	if err != nil {
		log.Fatalf("Failed to load X509 key pair: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	// Create a simple handler
	http.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		sar := &authorizationv1.SubjectAccessReview{}
		if err := json.NewDecoder(r.Body).Decode(sar); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		sar.Status.Allowed = false
		sar.Status.Denied = false
		sar.Status.Conditions = []authorizationv1.SubjectAccessReviewCondition{
			{
				Condition: "has(object.metasdata.labels) && has(object.metadata.labels.foo) && object.metadata.labels.foo == 'bar'",
			},
		}
		mw := io.MultiWriter(os.Stdout, w)
		json.NewEncoder(mw).Encode(sar)
	})

	// Start the server
	server := &http.Server{
		Addr:      "localhost:4321",
		TLSConfig: tlsConfig,
	}

	fmt.Println("Starting HTTPS server on https://localhost:4321, config file: ", webhookConfigFile)
	log.Fatal(server.ListenAndServeTLS("", ""))
}

// TestAuthzSelectorsLibraryEnabled ensures that the authzselectors library feature enablement works properly.
// CEL envs and compilers cached per process mean this must be the only test in this package.
func TestConditionalAuthz(t *testing.T) {
	/*if _, initialized := environment.AuthzSelectorsLibraryEnabled(); initialized {
		// This ensures CEL environments don't get initialized during init(),
		// before they can be informed by configured feature gates.
		// If this check fails, uncomment the debug.PrintStack() when the authz selectors
		// library is first initialized to find the culprit, and modify it to be lazily initialized on first use.
		t.Fatalf("authz selector library was initialized before feature gates were finalized (possibly from an init() or package variable)")
	}*/

	featureEnabled := true
	webhookConfigFile := "/tmp/webhook-config.yaml"

	// Start the server with the desired feature enablement
	server, err := apiservertesting.StartTestServer(t, nil, []string{
		fmt.Sprintf("--feature-gates=SubjectAccessReviewConditions=%v", featureEnabled),
		"--authorization-webhook-config-file=" + webhookConfigFile,
		"--authorization-mode=Webhook",
		"--authorization-webhook-version=v1",
	}, framework.SharedEtcd())
	if err != nil {
		t.Fatal(err)
	}
	defer server.TearDownFn()

	// Ensure the authz selectors library was initialzed and saw the right feature enablement
	/*if gotEnabled, initialized := environment.AuthzSelectorsLibraryEnabled(); !initialized {
		t.Fatalf("authz selector library was not initialized during API server construction")
	} else if gotEnabled != featureEnabled {
		t.Fatalf("authz selector library enabled=%v, expected %v", gotEnabled, featureEnabled)
	}*/

	// Attempt to create API objects using the fieldSelector and labelSelector authorizer functions,
	// and ensure they are only allowed when the feature is enabled.

	cfg := rest.CopyConfig(server.ClientConfig)
	cfg.Impersonate.UserName = "system:serviceaccount:default:default"
	cfg.Impersonate.Groups = []string{"system:serviceaccounts"}

	c, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("Failed to create clientset: %v", err)
	}
	/*crdClient, err := extclientset.NewForConfig(server.ClientConfig)
	if err != nil {
		t.Fatalf("Failed to create clientset: %v", err)
	}*/
	ctx := context.Background()
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "default",
			Labels:    map[string]string{
				//"foo": "bar",
			},
		},
		StringData: map[string]string{
			"hello": "hello",
		},
	}
	sec, err = c.CoreV1().Secrets("default").Create(ctx, sec, metav1.CreateOptions{})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(sec)
	//t.Errorf("test")
}
