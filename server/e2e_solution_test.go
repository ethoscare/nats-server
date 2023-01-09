package server

import (
	"fmt"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func startCloud(t *testing.T, serverConfig []byte, cloudPort int) (*Server, string) {
	configStr := fmt.Sprintf(string(serverConfig), strconv.Itoa(cloudPort))
	cloudConfig := createConfFile(t, []byte(configStr))
	cloudServer, _ := RunServerWithConfig(cloudConfig)
	return cloudServer, cloudConfig
}

func startStore(t *testing.T, serverConfig []byte, hubPort int, hubUser string, storeId string, storePort int) (*Server, string) {
	u, err := url.Parse(fmt.Sprintf("nats-leaf://%s:s3cr3t@localhost:%d", hubUser, hubPort))
	if err != nil {
		t.Fatalf("Error parsing url: %v", err)
	}
	configStr := fmt.Sprintf(string(serverConfig), u.String(), storeId, strconv.Itoa(storePort))
	storeConfig := createConfFile(t, []byte(configStr))
	storeServer, _ := RunServerWithConfig(storeConfig)
	time.Sleep(1 * time.Second)
	checkLeafNodeConnectedCount(t, storeServer, 1)
	return storeServer, storeConfig
}

func TestE2ERetailSolutionRetailFleetBus(t *testing.T) {
	/*
			E2E configuration for a retail cloud application accounts interacting bi-directionally with a fleet of
			retail stores.  Each retail store has multiple store application accounts.  Tests the topology of a hub with
			multiple leafs (cloud with multiple edges) where the leafs are inherently "untrusted" by the hub (i.e. hub-resident
			controls must protect against "rogue" stores).

			Store NATS configuration has a unique RETAIL cloud credential (with suitable permissions).
		    Store NATS configuration needs to know the store id of its instance.
			Store NATS configuration imports messages from each store app by unique app name.
			Store does not need to know cloud app names.
			Store apps have a unique app name.
			Store apps do not need to know the store id they are executing in.

			Cloud NATS configuration imports messages from each cloud app by unique app name.
			Cloud apps have a unique app name.
			Cloud does not need to know store app names.

			A cloud app publishes as: bus.retail.{app name}.{class}.{store id}.>
				bus.retail.{app name}.{class}.2.> to publish messages that will be received by store id 2 only
				bus.retail.{app name}.{class}.ALL.> to publish messages that will be received by all stores
				bus.retail.{app name}.{class}.NONE.> to publish messages that will be received by no stores (only cloud apps)

			A cloud app subscribes as: bus.retail.{app name}.{class}.{store id}.>
				bus.retail.> to see all publishes from both cloud and store
				bus.retail.CLOUD-APP-2.> to see all publishes from cloud app CLOUD-APP-2 only
				bus.retail.STORE.> to see all publishes from stores only
				bus.retail.STORE.*.2.> to see publishes just from store id 2)

			A store app publishes as: bus.store.{app name}.{class}.>

			A store app subscribes as: bus.store.{app name}.{class}.>
				bus.store.> to see all publishes from apps in the same store and cloud app publishes shared with the store
				bus.store.APP-3.> to see all publishes from a specific store app in the same store
				bus.store.CLOUD.> to see all publishes just from cloud apps

			Cloud apps and store apps can be configured to receive only specific classes (e.g. data classificaiton) of messages
			through specific import specification.  See store app APP-2 import below where only C4 messages from cloud apps
			and other same-store apps will be seen by APP-2.
	*/
	cloudConfig := []byte(`
		port: %[1]s
		leafnodes: {
			listen: "127.0.0.1:-1"
		}
	
		accounts: {
			RETAIL: {
				users: [ 
					{
						user: "user-retail-admin", password: "s3cr3t"
					}
					{ 
						user: "user-store-1", password: "s3cr3t"
						permissions: {
							# Solicitor-side (leaf-side is the solicitor, hub-side is the solicited) sees reversed publish/subscribe perms

							# Uplink
							# Subscription for bus.retail.STORE.*.1.> passed to Leaf
							# Leaf may publish bus.retail.STORE.*.1.> to Hub
							# Subscription for bus.store.> is passed to the Hub
							# Any rogue bus.store.> publishes to hub not exported from RETAIL

							publish: [ "bus.store.>", "bus.retail.STORE.*.1.>" ]

							# Downlink
							# Subscription for bus.store.CLOUD.*.1.> and bus.store.CLOUD.*.ALL.> passed to Hub
							# Hub may publish bus.store.CLOUD.*.1.> and bus.store.CLOUD.*.ALL.> to Leaf
							# Subscription for bus.retail.> passed to Leaf
							# Any rogue bus.retail.> subscribes from hub not exported to RETAIL

							subscribe: [ "bus.retail.>", "bus.store.CLOUD.*.1.>", "bus.store.CLOUD.*.ALL.>" ]
						}
					}
					{ 
						user: "user-store-2", password: "s3cr3t"
						permissions: {
							publish: [ "bus.store.>", "bus.retail.STORE.*.2.>" ]
							subscribe: [ "bus.retail.>", "bus.store.CLOUD.*.2.>", "bus.store.CLOUD.*.ALL.>" ]
						}
					}
				]
				exports: [
					# uplink
					{ stream: "bus.retail.STORE.*.*.>" }
				]
				imports: [
					# downlink
					{ stream: { account: "CLOUD-APP-1", subject: "bus.retail.CLOUD-APP-1.*.*.>" }, to: "bus.store.CLOUD.*.*.>" }
					{ stream: { account: "CLOUD-APP-2", subject: "bus.retail.CLOUD-APP-2.*.*.>" }, to: "bus.store.CLOUD.*.*.>" }
					{ stream: { account: "CLOUD-APP-3", subject: "bus.retail.CLOUD-APP-3.*.*.>" }, to: "bus.store.CLOUD.*.*.>" }
				]
			}
			CLOUD-APP-1: {
				users: [ { user: "user-cloud-app-1", password: "s3cr3t" } ]
				exports: [
					{ stream: "bus.retail.CLOUD-APP-1.*.*.>" }
				]
				imports: [
					{ stream: { account: "RETAIL", subject: "bus.retail.STORE.*.*.>" } }
					{ stream: { account: "CLOUD-APP-2", subject: "bus.retail.CLOUD-APP-2.*.*.>" } }
					{ stream: { account: "CLOUD-APP-3", subject: "bus.retail.CLOUD-APP-3.*.*.>" } }
				]
			}
			CLOUD-APP-2: {
				users: [ { user: "user-cloud-app-2", password: "s3cr3t" } ]
				exports: [
					{ stream: "bus.retail.CLOUD-APP-2.*.*.>" }
				]
				# CLOUD-APP-2 only receives Classification 4 messages
				imports: [
					{ stream: { account: "RETAIL", subject: "bus.retail.STORE.C4.*.>" } }
					{ stream: { account: "CLOUD-APP-1", subject: "bus.retail.CLOUD-APP-1.C4.*.>" } }
					{ stream: { account: "CLOUD-APP-3", subject: "bus.retail.CLOUD-APP-3.C4.*.>" } }
				]
			}
			CLOUD-APP-3: {
				users: [ { user: "user-cloud-app-3", password: "s3cr3t" } ]
				exports: [
					{ stream: "bus.retail.CLOUD-APP-3.*.*.>" }
				]
				imports: [
					{ stream: { account: "RETAIL", subject: "bus.retail.STORE.*.*.>" } }
					{ stream: { account: "CLOUD-APP-1", subject: "bus.retail.CLOUD-APP-1.*.*.>" } }
					{ stream: { account: "CLOUD-APP-2", subject: "bus.retail.CLOUD-APP-2.*.*.>" } }
				]
			}
			SYS: {
				users: [ { user: "System", password: "s3cr3t" } ]
			}
		}
		system_account: "SYS"
	`)

	storeConfig := []byte(`
		port: %[3]s
		leaf {
			# RETAIL (hub) <-> STORE (leaf)
			remotes [
				{ url: "%[1]s", account: "STORE" }
			]
		}

		accounts: {
			STORE: {
				users: [ { user: "user-store-admin", password: "s3cr3t" } ]
				exports: [
					# downlink
					{ stream: "bus.store.CLOUD.*.%[2]s.>" }
					{ stream: "bus.store.CLOUD.*.ALL.>" }
				]
				imports: [
					# uplink
					{ stream: { account: "APP-1", subject: "bus.store.APP-1.*.>"}, to: "bus.retail.STORE.*.%[2]s.>" }
					{ stream: { account: "APP-2", subject: "bus.store.APP-2.*.>"}, to: "bus.retail.STORE.*.%[2]s.>" }
					{ stream: { account: "APP-3", subject: "bus.store.APP-3.*.>"}, to: "bus.retail.STORE.*.%[2]s.>" }
				]
			}
			APP-1: {
				users: [ { user: "user-app-1", password: "s3cr3t" } ]
				exports: [
					{ stream: "bus.store.APP-1.*.>" }
				]
				imports: [
					{ stream: { account: "STORE", subject: "bus.store.CLOUD.*.%[2]s.>" }, to: "bus.store.CLOUD.*.>" }
					{ stream: { account: "STORE", subject: "bus.store.CLOUD.*.ALL.>" }, to: "bus.store.CLOUD.*.>" }
					{ stream: { account: "APP-2", subject: "bus.store.APP-2.*.>" } }
					{ stream: { account: "APP-3", subject: "bus.store.APP-3.*.>" } }
				]
			}
			APP-2: {
				users: [ { user: "user-app-2", password: "s3cr3t" } ]
				exports: [
					{ stream: "bus.store.APP-2.*.>" }
				]
				imports: [
					# APP-2 in store only allowed to receive Classification 4 messages
					{ stream: { account: "STORE", subject: "bus.store.CLOUD.C4.%[2]s.>" }, to: "bus.store.CLOUD.C4.>" }
					{ stream: { account: "STORE", subject: "bus.store.CLOUD.C4.ALL.>" }, to: "bus.store.CLOUD.C4.>" }
					{ stream: { account: "APP-1", subject: "bus.store.APP-1.C4.>" } }
					{ stream: { account: "APP-3", subject: "bus.store.APP-3.C4.>" } }
				]
			}
			APP-3: {
				users: [ { user: "user-app-3", password: "s3cr3t" } ]
				exports: [
					{ stream: "bus.store.APP-3.*.>" }
				]
				imports: [
					{ stream: { account: "STORE", subject: "bus.store.CLOUD.*.%[2]s.>" }, to: "bus.store.CLOUD.*.>" }
					{ stream: { account: "STORE", subject: "bus.store.CLOUD.*.ALL.>" }, to: "bus.store.CLOUD.*.>" }
					{ stream: { account: "APP-1", subject: "bus.store.APP-1.*.>" } }
					{ stream: { account: "APP-2", subject: "bus.store.APP-2.*.>" } }
				]
			}
			SYS: {
				users: [ { user: "system", password: "s3cr3t" } ]
			}
		}
		system_account: "SYS"
	`)

	cloud, cloudConfigFile := startCloud(t, cloudConfig, -1)
	require_True(t, cloud != nil)
	require_True(t, cloudConfigFile != "")
	defer cloud.Shutdown()
	defer removeFile(t, cloudConfigFile)

	store1, storeConfigFile1 := startStore(t, storeConfig, cloud.leafNodeInfo.Port, "user-store-1", "1", -1)
	require_True(t, store1 != nil)
	require_True(t, storeConfigFile1 != "")
	defer store1.Shutdown()
	defer removeFile(t, storeConfigFile1)

	store2, storeConfigFile2 := startStore(t, storeConfig, cloud.leafNodeInfo.Port, "user-store-2", "2", -1)
	require_True(t, store2 != nil)
	require_True(t, storeConfigFile2 != "")
	defer store2.Shutdown()
	defer removeFile(t, storeConfigFile2)

	// Uncomment and change cloudPort and storePort ports to fixed numbers (e.g. 4222, 4322, 4422) for quick ad-hoc environment
	//fmt.Printf("cloud url: [%s]\n", cloud.clientConnectURLs[0])
	//fmt.Printf("store1 url: [%s]\n", store1.clientConnectURLs[0])
	//fmt.Printf("store2 url: [%s]\n", store2.clientConnectURLs[0])
	//select {}

	// Cloud app pub to specific store
	// nats --server localhost:4222 --user user-cloud-app-1 --password s3cr3t pub bus.retail.CLOUD-APP-1.C4.2.order.blah.blah "hello from cloud-app-1 {{.TimeStamp}}"
	// Other cloud apps should see, only store 2 should see

	// Cloud app pub to all stores
	// nats --server localhost:4222 --user user-cloud-app-1 --password s3cr3t pub bus.retail.CLOUD-APP-1.C4.ALL.order.blah.blah "hello from cloud-app-1 {{.TimeStamp}}"
	// Other cloud apps should see, all stores should see

	// Cloud app pub to other cloud apps only
	// nats --server localhost:4222 --user user-cloud-app-1 --password s3cr3t pub bus.retail.CLOUD-APP-1.C4.NONE.order.blah.blah "hello from cloud-app-1 {{.TimeStamp}}"
	// Other cloud apps should see, no stores should see

	// Cloud app subs to all retail bus messages (cloud origin and store origin)
	// nats --server localhost:4222 --user user-cloud-app-3 --password s3cr3t sub "bus.retail.>"
	// Should see messages published from itself, another cloud-app, and a store

	// Cloud app subs to all retail bus messages from a specific cloud app
	// nats --server localhost:4222 --user user-cloud-app-3 --password s3cr3t sub "bus.retail.CLOUD-APP-2.>"
	// Should see messages published from CLOUD-APP-2 only

	// Cloud app subs to all retail bus messages from store apps only
	// nats --server localhost:4222 --user user-cloud-app-3 --password s3cr3t sub "bus.retail.STORE.>"
	// Should see messages published from store apps only

	// Cloud app subs to all retail bus messages from a specific store only
	// nats --server localhost:4222 --user user-cloud-app-3 --password s3cr3t sub "bus.retail.STORE.*.2.>"
	// Should see messages published from store 2 only

	// Store app pubs
	// nats --server localhost:4322 --user user-app-1 --password s3cr3t pub "bus.store.APP-1.C1.order.blah.blah" "hello from store1 app1 {{.TimeStamp}}"
	// Cloud apps should see, same-store apps (only) should see

	// Store app subs to all store bus messages (cloud origin and same-store origin)
	// nats --server localhost:4322 --user user-app-3  --password s3cr3t sub "bus.store.>
	// Should see messages published from any same-store app and cloud apps

	// Store app subs to a specific store app
	// nats --server localhost:4322 --user user-app-3  --password s3cr3t sub "bus.store.APP-2.>
	// Should see messages published from only that store app and only same-store instance

	// Store app subs to store bus messages from cloud only
	// nats --server localhost:4322 --user user-app-3  --password s3cr3t sub "bus.store.CLOUD.>
	// Should see messages published from only CLOUD apps
	// Should see messages from CLOUD only intended for the specific store (or ALL stores)

	// Store app configured only for Classification 4 ("C4") messages should see only C4 messages
	// nats --server localhost:4322 --user user-app-2  --password s3cr3t sub "bus.store.>
	// Should see only C4 messages from other same-store apps and cloud (where APP-2 configured with C4 restriction)

}
