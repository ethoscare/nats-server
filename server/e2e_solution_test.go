package server

import (
	"fmt"
	"github.com/nats-io/nats.go"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func startRetailCloud(t *testing.T, serverConfig []byte, cloudPort int, serverName string, httpPort int) (*Server, string) {
	configStr := fmt.Sprintf(string(serverConfig), strconv.Itoa(cloudPort), serverName, strconv.Itoa(httpPort))
	cloudConfig := createConfFile(t, []byte(configStr))
	cloudServer, _ := RunServerWithConfig(cloudConfig)
	return cloudServer, cloudConfig
}

func startRetailStore(t *testing.T, serverConfig []byte, hubPort int, hubUser string, storeId string, storePort int, serverName string, httpPort int) (*Server, string) {
	u, err := url.Parse(fmt.Sprintf("nats-leaf://%s:s3cr3t@localhost:%d", hubUser, hubPort))
	if err != nil {
		t.Fatalf("Error parsing url: %v", err)
	}
	configStr := fmt.Sprintf(string(serverConfig), u.String(), storeId, strconv.Itoa(storePort), serverName, strconv.Itoa(httpPort))
	storeConfig := createConfFile(t, []byte(configStr))
	storeServer, _ := RunServerWithConfig(storeConfig)
	time.Sleep(1 * time.Second)
	checkLeafNodeConnectedCount(t, storeServer, 1)
	return storeServer, storeConfig
}

func createRetailClient(t *testing.T, s *Server, u string) *nats.Conn {
	// Create test clients
	c, err := nats.Connect(fmt.Sprintf("%s:%s@%s", u, "s3cr3t", s.getClientConnectURLs()[0]))
	require_True(t, err == nil)
	require_True(t, c != nil)
	return c
}

func createRetailFleetBusClients(t *testing.T, cloud *Server, store1 *Server, store2 *Server) map[string]*nats.Conn {
	connMap := make(map[string]*nats.Conn)
	cloudUsers := []string{"user-retail-admin", "user-cloud-app-1", "user-cloud-app-2", "user-cloud-app-3"}
	storeUsers := []string{"user-store-admin", "user-app-1", "user-app-2", "user-app-3"}

	if cloud != nil {
		for _, user := range cloudUsers {
			connMap[user] = createRetailClient(t, cloud, user)
		}
	}
	if store1 != nil {
		for _, user := range storeUsers {
			connMap["store1-"+user] = createRetailClient(t, store1, user)
		}
	}
	if store2 != nil {
		for _, user := range storeUsers {
			connMap["store2-"+user] = createRetailClient(t, store2, user)
		}
	}
	return connMap
}

func closeRetailFleetBusClients(t *testing.T, cs map[string]*nats.Conn) {
	t.Helper()
	for _, c := range cs {
		c.Close()
	}
}

func resetRetailClientSub(t *testing.T, sub *nats.Subscription) {
	t.Helper()
	var err error
	for err == nil {
		_, err = sub.NextMsg(2 * time.Millisecond)
	}
}

func resetRetailClientSubSet(t *testing.T, subs map[string]*nats.Subscription) {
	t.Helper()
	for _, sub := range subs {
		resetRetailClientSub(t, sub)
	}
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

	var err error

	cloudConfig := []byte(`
		port: %[1]s
		server_name: %[2]s
		http_port: %[3]s
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
							# Leaf Connection
							# Solicitor-side (leaf-side is the solicitor, hub-side is the solicited) applies 
							# pub/sub perms reversed.
							#
							# Both solicited and solicitor transfer any respective client subs to create cross-membrane
							# subscription interest. The transferred subs are pruned by permission scope.

							# Uplink
							# Subscription for bus.retail.STORE.*.1.> passed to Leaf
							# Leaf may publish bus.retail.STORE.*.1.> to Hub
							# Subscription for bus.store.> is passed to the Hub
							# Any rogue bus.store.> publishes to hub not exported from RETAIL
							# Issue #1: rogue bus.retail.STORE.> subscription from any store

							publish: [ "bus.store.>", "bus.retail.STORE.*.1.>" ]

							# Downlink
							# Subscription for bus.store.CLOUD.*.1.> and bus.store.CLOUD.*.ALL.> passed to Hub
							# Hub may publish bus.store.CLOUD.*.1.> and bus.store.CLOUD.*.ALL.> to Leaf
							# Subscription for bus.retail.> passed to Leaf
							# Any rogue bus.retail.> subscribes from hub not exported to RETAIL
							# Issue #2: rogue bus.store.CLOUD.> publish down to any store 

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
		server_name: %[4]s
		http_port: %[5]s
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

	cloud, cloudConfigFile := startRetailCloud(t, cloudConfig, 4222, "cloud", 8222)
	require_True(t, cloud != nil)
	require_True(t, cloudConfigFile != "")
	defer cloud.Shutdown()
	defer removeFile(t, cloudConfigFile)

	store1, storeConfigFile1 := startRetailStore(t, storeConfig, cloud.leafNodeInfo.Port, "user-store-1", "1", 4322, "store1", 8322)
	require_True(t, store1 != nil)
	require_True(t, storeConfigFile1 != "")
	defer store1.Shutdown()
	defer removeFile(t, storeConfigFile1)

	store2, storeConfigFile2 := startRetailStore(t, storeConfig, cloud.leafNodeInfo.Port, "user-store-2", "2", 4422, "store2", 8422)
	require_True(t, store2 != nil)
	require_True(t, storeConfigFile2 != "")
	defer store2.Shutdown()
	defer removeFile(t, storeConfigFile2)

	// Create test clients and subs
	c := createRetailFleetBusClients(t, cloud, store1, store2)
	defer closeRetailFleetBusClients(t, c)

	subs1 := make(map[string]*nats.Subscription)
	subs1["user-cloud-app-1"], err = c["user-cloud-app-1"].SubscribeSync("bus.retail.>")
	if err != nil {
		t.Fatalf("expected to be able to subscribe: %v", err)
	}
	subs1["user-cloud-app-2"], err = c["user-cloud-app-2"].SubscribeSync("bus.retail.>")
	if err != nil {
		t.Fatalf("expected to be able to subscribe: %v", err)
	}
	subs1["user-cloud-app-3"], err = c["user-cloud-app-3"].SubscribeSync("bus.retail.>")
	if err != nil {
		t.Fatalf("expected to be able to subscribe: %v", err)
	}
	subs1["store1-user-app-1"], err = c["store1-user-app-1"].SubscribeSync("bus.store.>")
	if err != nil {
		t.Fatalf("expected to be able to subscribe: %v", err)
	}
	subs1["store1-user-app-2"], err = c["store1-user-app-2"].SubscribeSync("bus.store.>")
	if err != nil {
		t.Fatalf("expected to be able to subscribe: %v", err)
	}
	subs1["store1-user-app-3"], err = c["store1-user-app-3"].SubscribeSync("bus.store.>")
	if err != nil {
		t.Fatalf("expected to be able to subscribe: %v", err)
	}
	subs1["store2-user-app-1"], err = c["store2-user-app-1"].SubscribeSync("bus.store.>")
	if err != nil {
		t.Fatalf("expected to be able to subscribe: %v", err)
	}
	subs1["store2-user-app-2"], err = c["store2-user-app-2"].SubscribeSync("bus.store.>")
	if err != nil {
		t.Fatalf("expected to be able to subscribe: %v", err)
	}
	subs1["store2-user-app-3"], err = c["store2-user-app-3"].SubscribeSync("bus.store.>")
	if err != nil {
		t.Fatalf("expected to be able to subscribe: %v", err)
	}

	// Time for store subcription interest to propogate up to cloud (for downlink) and down to store (for uplink)
	time.Sleep(100 * time.Millisecond)

	// Cloud app pub to specific store (#1)
	err = c["user-cloud-app-1"].Publish("bus.retail.CLOUD-APP-1.C4.1.order.blah.blah", []byte("from cloud-app-1 to store 1"))
	if err != nil {
		t.Fatalf("expected to be able to publish: %v", err)
	}
	checkSubsPending(t, subs1["user-cloud-app-1"], 1)  // itself
	checkSubsPending(t, subs1["user-cloud-app-2"], 1)  // another cloud app
	checkSubsPending(t, subs1["store2-user-app-1"], 0) // a store 2 app
	checkSubsPending(t, subs1["store1-user-app-1"], 1) // a store 1 app
	resetRetailClientSubSet(t, subs1)

	// Cloud app pub to specific store (#2)
	err = c["user-cloud-app-1"].Publish("bus.retail.CLOUD-APP-1.C4.2.order.blah.blah", []byte("from cloud-app-1 to store 2"))
	if err != nil {
		t.Fatalf("expected to be able to publish: %v", err)
	}
	checkSubsPending(t, subs1["user-cloud-app-1"], 1)  // itself
	checkSubsPending(t, subs1["user-cloud-app-2"], 1)  // another cloud app
	checkSubsPending(t, subs1["store2-user-app-1"], 1) // a store 2 app
	checkSubsPending(t, subs1["store1-user-app-1"], 0) // a store 1 app
	resetRetailClientSubSet(t, subs1)

	// Cloud app pub to all stores
	err = c["user-cloud-app-1"].Publish("bus.retail.CLOUD-APP-1.C4.ALL.order.blah.blah", []byte("from cloud-app-1 to all stores"))
	if err != nil {
		t.Fatalf("expected to be able to publish: %v", err)
	}
	checkSubsPending(t, subs1["store1-user-app-1"], 1) // a store 1 app
	checkSubsPending(t, subs1["store2-user-app-1"], 1) // a store 2 app
	resetRetailClientSubSet(t, subs1)

	// Cloud app pub to other cloud apps only
	err = c["user-cloud-app-1"].Publish("bus.retail.CLOUD-APP-1.C4.NONE.order.blah.blah", []byte("from cloud-app-1 to no stores"))
	if err != nil {
		t.Fatalf("expected to be able to publish: %v", err)
	}
	checkSubsPending(t, subs1["user-cloud-app-2"], 1)  // a cloud app
	checkSubsPending(t, subs1["store1-user-app-1"], 0) // a store 1 app
	checkSubsPending(t, subs1["store2-user-app-1"], 0) // a store 2 app
	resetRetailClientSubSet(t, subs1)

	// Uncomment below and change cloudPort, storePort, and httpPort to fixed numbers (e.g. 4222/8222, 4322/8322, 4422/8422) for quick ad-hoc environment
	fmt.Printf("ad-hoc testing")
	select {}

	// Cloud app subs to all retail bus messages from a specific cloud app only
	adhocSub, err := c["user-cloud-app-3"].SubscribeSync("bus.retail.CLOUD-APP-2.>")
	if err != nil {
		t.Fatalf("expected to be able to subscribe: %v", err)
	}
	err = c["user-cloud-app-2"].Publish("bus.retail.CLOUD-APP-2.C4.42.order.blah.blah", []byte("from cloud-app-2"))
	if err != nil {
		t.Fatalf("expected to be able to publish: %v", err)
	}
	err = c["user-cloud-app-1"].Publish("bus.retail.CLOUD-APP-1.C4.69.order.blah.blah", []byte("from cloud-app-1"))
	if err != nil {
		t.Fatalf("expected to be able to publish: %v", err)
	}
	checkSubsPending(t, adhocSub, 1)
	adhocSub.Unsubscribe()

	// Store app pub to cloud apps, other same-store apps, and itself
	err = c["store1-user-app-1"].Publish("bus.store.APP-1.C4.order.blah.blah", []byte("from store1-user-app-1"))
	if err != nil {
		t.Fatalf("expected to be able to publish: %v", err)
	}
	checkSubsPending(t, subs1["store1-user-app-1"], 1) // itself
	checkSubsPending(t, subs1["store1-user-app-2"], 1) // another same-store app
	checkSubsPending(t, subs1["user-cloud-app-1"], 1)  // a cloud app
	checkSubsPending(t, subs1["store2-user-app-1"], 0) // A different store app

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
