//go:build windows

package server

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"testing"
	"time"
)

func runPowershellScript(scriptFile string, args []string) error {
	_ = args
	psExec, _ := exec.LookPath("powershell.exe")
	execArgs := []string{psExec, "-command", fmt.Sprintf("& '%s'", scriptFile)}

	cmdImport := &exec.Cmd{
		Path:   psExec,
		Args:   execArgs,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}
	return cmdImport.Run()
}

func runConfiguredLeaf(t *testing.T, hubPort int, certStore string, matchBy string, match string) {

	// Fire up the leaf
	u, err := url.Parse(fmt.Sprintf("nats://localhost:%d", hubPort))
	if err != nil {
		t.Fatalf("Error parsing url: %v", err)
	}

	configStr := fmt.Sprintf(string([]byte(`
		port: -1
		leaf {
			remotes [
				{
					url: "%s"
					tls {
						cert_store: "%s"
						cert_match_by: "%s"
						cert_match: "%s"

						# Above should be equivalent to:
						# cert_file: "../test/configs/certs/tlsauth/client.pem"
						# key_file: "../test/configs/certs/tlsauth/client-key.pem"

						ca_file: "../test/configs/certs/tlsauth/ca.pem"
						timeout: 5
					}
				}
			]
		}
	`)), u.String(), certStore, matchBy, match)

	leafConfig := createConfFile(t, []byte(configStr))
	defer removeFile(t, leafConfig)
	leafServer, _ := RunServerWithConfig(leafConfig)
	defer leafServer.Shutdown()

	// After client verify, hub will match by SAN email, SAN dns, and Subject (in that order)
	// Our test client specifies Subject only so we should match on that...

	// A little settle time
	time.Sleep(1 * time.Second)
	checkLeafNodeConnectedCount(t, leafServer, 1)
}

// TestLeafTLSWindowsCertStore tests the topology of two NATS Servers connected as leaf and hub with authentication of
// leaf to hub via mTLS with leaf's certificate and signing key provisioned in the Windows certificate store.
func TestLeafTLSWindowsCertStore(t *testing.T) {

	// Client Identity (client.pem)
	// Issuer: O = Synadia Communications Inc., OU = NATS.io, CN = localhost
	// Subject: OU = NATS.io, CN = example.com

	// Provision Windows cert store with client cert and secret
	err := runPowershellScript("../test/configs/certs/tlsauth/import-p12-client.ps1", nil)
	if err != nil {
		t.Fatalf("expected powershell provision to succeed: %s", err.Error())
	}

	// Fire up the hub
	hubConfig := createConfFile(t, []byte(`
		port: -1
		leaf {
			listen: "127.0.0.1:-1"
			tls {
				ca_file: "../test/configs/certs/tlsauth/ca.pem"
				cert_file: "../test/configs/certs/tlsauth/server.pem"
				key_file:  "../test/configs/certs/tlsauth/server-key.pem"
				timeout: 5
				verify_and_map: true
			}
		}

		accounts: {
			AcctA: {
			  users: [ {user: "OU = NATS.io, CN = example.com"} ]
			},
			AcctB: {
			  users: [ {user: UserB1} ]
			},
			SYS: {
				users: [ {user: System} ]
			}
		}
		system_account: "SYS"          
	`))
	defer removeFile(t, hubConfig)
	hubServer, hubOptions := RunServerWithConfig(hubConfig)
	defer hubServer.Shutdown()

	testCases := []struct {
		certStore   string
		certMatchBy string
		certMatch   string
	}{
		{"WindowsCurrentUser", "Subject", "example.com"},
		{"WindowsCurrentUser", "Issuer", "Synadia Communications Inc."},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s by %s match %s", tc.certStore, tc.certMatchBy, tc.certMatch), func(t *testing.T) {
			runConfiguredLeaf(t, hubOptions.LeafNode.Port, tc.certStore, tc.certMatchBy, tc.certMatch)
		})
	}
}
