package server

import (
	"fmt"
	"net/url"
	"testing"
	"time"
)

func startStore(t *testing.T, cloudPort int, cloudUser string) (*Server, string) {
	u, err := url.Parse(fmt.Sprintf("nats-leaf://%s:s3cr3t@localhost:%d", cloudUser, cloudPort))
	if err != nil {
		t.Fatalf("Error parsing url: %v", err)
	}

	configStr := fmt.Sprintf(string([]byte(`
		port: -1
		leaf {
			remotes [
				{ url: "%s", account: "STORE" }
			]
		}

		accounts: {
			# Aggregation point for messages crossing Cloud-Store membrane
			# Bound to STORE-X in Hub
			STORE: {
				users: [ { user: "user-cloud", password: "s3cr3t" } ]
				exports: [
					{
						stream: "store.*.>"
						accounts: [
							"APP-1"
							"APP-2"
							"APP-3"
						]
					}
				]
				imports: [
					{ stream: { account: "APP-1", subject: "store.*.>" }, prefix: "bus.APP-1" }
					{ stream: { account: "APP-2", subject: "store.*.>" }, prefix: "bus.APP-2" }
					{ stream: { account: "APP-3", subject: "store.*.>" }, prefix: "bus.APP-3" }
				]
			}
			# APP-X is a store account for Application X in store
			APP-1: {
				users: [ { user: "user-app-1", password: "s3cr3t" } ]
				# Share Application X publishes with cloud (via STORE) and other store Applications
				exports: [
					{
						stream: "store.*.>"
						accounts: [
							"STORE"
							"APP-1"
							"APP-2"
							"APP-3"
						]
					}
				]
				imports: [
					# Ability to subscribe messages published by other store Applications and from cloud Applications
					{ stream: { account: "STORE", subject: "store.*.>" }, prefix: "bus.CLOUD" }
					{ stream: { account: "APP-1", subject: "store.*.>" }, prefix: "bus.APP-1" }
					{ stream: { account: "APP-2", subject: "store.*.>" }, prefix: "bus.APP-2" }
					{ stream: { account: "APP-3", subject: "store.*.>" }, prefix: "bus.APP-3" }
				]
			}
			APP-2: {
				users: [ { user: "user-app-2", password: "s3cr3t" } ]
				exports: [
					{
						stream: "store.*.>"
						accounts: [
							"STORE"
							"APP-1"
							"APP-2"
							"APP-3"
						]
					}
				]
				imports: [
					{ stream: { account: "STORE", subject: "store.*.>" }, prefix: "bus.CLOUD" }
					{ stream: { account: "APP-1", subject: "store.*.>" }, prefix: "bus.APP-1" }
					{ stream: { account: "APP-2", subject: "store.*.>" }, prefix: "bus.APP-2" }
					{ stream: { account: "APP-3", subject: "store.*.>" }, prefix: "bus.APP-3" }
				]
			}
			APP-3: {
				users: [ { user: "user-app-3", password: "s3cr3t" } ]
				exports: [
					{
						stream: "store.*.>"
						accounts: [
							"STORE"
							"APP-1"
							"APP-2"
							"APP-3"
						]
					}
				]
				imports: [
					{ stream: { account: "STORE", subject: "store.*.>" }, prefix: "bus.CLOUD" }
					{ stream: { account: "APP-1", subject: "store.*.>" }, prefix: "bus.APP-1" }
					{ stream: { account: "APP-2", subject: "store.*.>" }, prefix: "bus.APP-2" }
					{ stream: { account: "APP-3", subject: "store.*.>" }, prefix: "bus.APP-3" }
				]
			}
			SYS: {
				users: [ { user: "system", password: "s3cr3t" } ]
			}
		}
		system_account: "SYS"
	`)), u.String())

	storeConfig := createConfFile(t, []byte(configStr))
	storeServer, _ := RunServerWithConfig(storeConfig)

	// A little settle time
	time.Sleep(1 * time.Second)
	checkLeafNodeConnectedCount(t, storeServer, 1)

	return storeServer, storeConfig
}

// TestE2ESolution1 tests the topology of a hub with multiple leafs (cloud with multiple edges):
//
// 1. Cloud (hub) and all stores (leaves) are multi-account enabled
// 2. An account in cloud acts as a down-filtering/traffic direction for individual stores
// 3. Each store is identically configured, with exception of cloud credential
// 4. Cloud and all stores can publish on a common "store" subject hierarchy. Cloud sees as "retail" subject hierarchy
// 5. Cloud can subscribe to all messages (both published in cloud and in the stores) of the common subject hierarchy
// 6. Stores can subscribe to all messages published locally in their store on the common subject hierarchy
// 7. A store can subscribe to subject hierarchy messages (published by cloud) intended for that store only
// 8. Specific accounts of the cloud and stores may be further filtered by a classification subject token
//
// Cloud publishes as:
// retail.{class}.{store number}.>
// A store subscribes as:
// bus.{app code}.store.{class}.>
//
// A store publishes as:
// store.{class}.>
// Cloud subscribes as as:
// bus.{app code}.retail.{class}.{store number}.>

func TestE2ERetailSolution1(t *testing.T) {

	// TODO: messages published in store not traversing back to cloud-app-1 subscription to bus.>

	cloudConfig := createConfFile(t, []byte(`
		port: -1
		leafnodes: {
			listen: "127.0.0.1:-1"
		}

		accounts: {
			# Account representating aggregate stores
			RETAIL: {
				users: [ { user: "user-retail", password: "s3cr3t" } ]
				exports: [
					# Publish point for all retail stores
					{ service: "retail.*.*.>" }

					# Share aggragate publishes from stores with other cloud accounts
					{ service: "bus.*.retail.*.*.>" }
					{ stream: "bus.*.retail.*.*.>" }

					# Messages published in cloud (to retail) down to specific store
					{ stream: "retail.*.1.>", accounts: [ "STORE-1" ] }
					{ stream: "retail.*.2.>", accounts: [ "STORE-2" ] }

					# Echo to self to allow bus.CLOUD
					{ stream: "retail.*.*.>", accounts: [ "RETAIL" ] }
				]
				imports: [
					# If this is implemented, we get a cycle error combined with CLOUD-APP-1 export/import
					# { stream: { account: "RETAIL", subject: "retail.*.*.>" }, prefix: "bus.CLOUD" } 
				]
			}
			# STORE-X in Hub (bound to STORE at each Leaf)
			STORE-1: {
				users: [ { user: "user-store-1", password: "s3cr3t" } ]
				imports: [
					# Publish into RETAIL
					# Flip "store" token to "retail" token
					# Add store number
					# Store 1 can only publish as Store 1
					# ** These are direct publishes in RETAIL account at hub **

					{ service: { account: "RETAIL", subject: "bus.*.retail.*.1.>" }, to: "bus.*.store.*.>" }
					
					# Subscribe from RETAIL
					# Flip "retail" token to "store" token
					# Remove store number
					# Store 1 can only subscribe to Store 1 addressed messages
					# ** These will be experienced as direct _publishes_ in STORE account at leaf **

					{ stream: { account: "RETAIL", subject: "retail.*.1.>" }, to: "store.*.>" }
				]
			}
			STORE-2: {
				users: [ { user: "user-store-2", password: "s3cr3t" } ]
				imports: [
					{ service: { account: "RETAIL", subject: "bus.*.retail.*.2.>" }, to: "bus.*.store.*.>" }
					{ stream: { account: "RETAIL", subject: "retail.*.2.>" }, to: "store.*.>" }
				]
			}
			CLOUD-APP-1: {
				users: [ { user: "user-cloud-app-1", password: "s3cr3t" } ]
				imports: [
					{ service: { account: "RETAIL", subject: "retail.*.*.>" } }
					# This should see store-origin messages, but not cloud-origin including my own...
					{ stream: { account: "RETAIL", subject: "bus.*.retail.*.*.>" } }
				]
			}
			SYS: {
				users: [ { user: "System", password: "s3cr3t" } ]
			}
		}
		system_account: "SYS"
	`))
	defer removeFile(t, cloudConfig)
	cloud, _ := RunServerWithConfig(cloudConfig)
	defer cloud.Shutdown()

	store1, storeConfig1 := startStore(t, cloud.leafNodeInfo.Port, "user-store-1")
	require_True(t, store1 != nil)
	require_True(t, storeConfig1 != "")
	defer removeFile(t, storeConfig1)
	defer store1.Shutdown()

	store2, storeConfig2 := startStore(t, cloud.leafNodeInfo.Port, "user-store-2")
	require_True(t, store2 != nil)
	require_True(t, storeConfig2 != "")
	defer removeFile(t, storeConfig2)
	defer store2.Shutdown()

	//fmt.Printf("cloud url: [%s]\n", cloud.clientConnectURLs[0])
	//fmt.Printf("store1 url: [%s]\n", store1.clientConnectURLs[0])
	//fmt.Printf("store2 url: [%s]\n", store2.clientConnectURLs[0])
	//
	// select {}

	//testCases := []struct {
	//	certStore   string
	//	certMatchBy string
	//	certMatch   string
	//}{
	//	{"WindowsCurrentUser", "Subject", "example.com"},
	//	{"WindowsCurrentUser", "Issuer", "Synadia Communications Inc."},
	//}
	//for _, tc := range testCases {
	//	t.Run(fmt.Sprintf("%s by %s match %s", tc.certStore, tc.certMatchBy, tc.certMatch), func(t *testing.T) {
	//		runConfiguredLeaf(t, hubOptions.LeafNode.Port, tc.certStore, tc.certMatchBy, tc.certMatch)
	//	})
	//}
}
