package main

import (
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
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	authorizationv1alpha1 "k8s.io/api/authorization/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Example conditional webhook authorizer for the integration tests.

func main() {

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
		requestBody, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer r.Body.Close()
		fmt.Println("request body: ", string(requestBody))

		tm := metav1.TypeMeta{}
		if err := json.Unmarshal(requestBody, &tm); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if tm.Kind == "SubjectAccessReview" {

			sar := &authorizationv1.SubjectAccessReview{}
			if err := json.Unmarshal(requestBody, sar); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			sar.Status.Allowed = false
			sar.Status.Denied = false

			if sar.Spec.ResourceAttributes != nil && sar.Spec.ResourceAttributes.Resource == "selfsubjectaccessreviews" {
				sar.Status.Allowed = true
			}

			// Respond by NoOpinion to everything but the default service account's secret requests
			if sar.Spec.User == "system:serviceaccount:default:default" && sar.Spec.ResourceAttributes != nil && sar.Spec.ResourceAttributes.Resource == "secrets" {
				sar.Status.ConditionsChain = []authorizationv1.SubjectAccessReviewConditionSet{
					{
						Conditions: []authorizationv1.SubjectAccessReviewCondition{
							{
								ID:        "labels-foo-bar",
								Type:      "opaque",
								Effect:    authorizationv1.SubjectAccessReviewConditionEffectAllow,
								Condition: "policy16",
								//Condition: "has(object.metadata.labels) && has(object.metadata.labels.foo) && object.metadata.labels.foo == 'bar'",
							},
						},
					},
				}
			}
			mw := io.MultiWriter(os.Stdout, w)
			json.NewEncoder(mw).Encode(sar)
			return
		}
		if tm.Kind == "AuthorizationConditionsReview" {
			ac := &authorizationv1alpha1.AuthorizationConditionsReview{}
			if err := json.Unmarshal(requestBody, ac); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			ac.Response = &authorizationv1alpha1.AuthorizationConditionsResponse{
				Allowed: false,
				Denied:  false,
			}
			if ac.Request.UserInfo.Username == "system:serviceaccount:default:default" &&
				ac.Request.Resource.Resource == "secrets" &&
				ac.Request.ConditionSet.Conditions[0].Condition == "policy16" {
				ac.Response.Allowed = true
			}
			mw := io.MultiWriter(os.Stdout, w)
			json.NewEncoder(mw).Encode(ac)
			return
		}
	})

	// Start the server
	server := &http.Server{
		Addr:      "localhost:4321",
		TLSConfig: tlsConfig,
	}

	fmt.Println("Starting HTTPS server on https://localhost:4321, config file: ", webhookConfigFile)
	log.Fatal(server.ListenAndServeTLS("", ""))
}
