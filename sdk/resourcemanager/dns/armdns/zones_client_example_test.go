//go:build go1.18
// +build go1.18

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.
// DO NOT EDIT.

package armdns_test

import (
	"context"
	"log"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
)

// Generated from example definition: https://github.com/Azure/azure-rest-api-specs/blob/987a8f38ab2a8359d085e149be042267a9ecc66f/specification/dns/resource-manager/Microsoft.Network/preview/2023-07-01-preview/examples/CreateOrUpdateZone.json
func ExampleZonesClient_CreateOrUpdate() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	clientFactory, err := armdns.NewClientFactory("<subscription-id>", cred, nil)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}
	res, err := clientFactory.NewZonesClient().CreateOrUpdate(ctx, "rg1", "zone1", armdns.Zone{
		Location: to.Ptr("Global"),
		Tags: map[string]*string{
			"key1": to.Ptr("value1"),
		},
	}, &armdns.ZonesClientCreateOrUpdateOptions{IfMatch: nil,
		IfNoneMatch: nil,
	})
	if err != nil {
		log.Fatalf("failed to finish the request: %v", err)
	}
	// You could use response here. We use blank identifier for just demo purposes.
	_ = res
	// If the HTTP response code is 200 as defined in example definition, your response structure would look as follows. Please pay attention that all the values in the output are fake values for just demo purposes.
	// res.Zone = armdns.Zone{
	// 	Name: to.Ptr("zone1"),
	// 	Type: to.Ptr("Microsoft.Network/dnsZones"),
	// 	ID: to.Ptr("/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/dnsZones/zone1"),
	// 	Location: to.Ptr("global"),
	// 	Tags: map[string]*string{
	// 		"key1": to.Ptr("value1"),
	// 	},
	// 	Etag: to.Ptr("00000000-0000-0000-0000-000000000000"),
	// 	Properties: &armdns.ZoneProperties{
	// 		MaxNumberOfRecordSets: to.Ptr[int64](5000),
	// 		NameServers: []*string{
	// 			to.Ptr("ns1-01.azure-dns.com"),
	// 			to.Ptr("ns2-01.azure-dns.net"),
	// 			to.Ptr("ns3-01.azure-dns.org"),
	// 			to.Ptr("ns4-01.azure-dns.info")},
	// 			NumberOfRecordSets: to.Ptr[int64](2),
	// 			ZoneType: to.Ptr(armdns.ZoneTypePublic),
	// 		},
	// 	}
}

// Generated from example definition: https://github.com/Azure/azure-rest-api-specs/blob/987a8f38ab2a8359d085e149be042267a9ecc66f/specification/dns/resource-manager/Microsoft.Network/preview/2023-07-01-preview/examples/DeleteZone.json
func ExampleZonesClient_BeginDelete() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	clientFactory, err := armdns.NewClientFactory("<subscription-id>", cred, nil)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}
	poller, err := clientFactory.NewZonesClient().BeginDelete(ctx, "rg1", "zone1", &armdns.ZonesClientBeginDeleteOptions{IfMatch: nil})
	if err != nil {
		log.Fatalf("failed to finish the request: %v", err)
	}
	_, err = poller.PollUntilDone(ctx, nil)
	if err != nil {
		log.Fatalf("failed to pull the result: %v", err)
	}
}

// Generated from example definition: https://github.com/Azure/azure-rest-api-specs/blob/987a8f38ab2a8359d085e149be042267a9ecc66f/specification/dns/resource-manager/Microsoft.Network/preview/2023-07-01-preview/examples/GetZone.json
func ExampleZonesClient_Get() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	clientFactory, err := armdns.NewClientFactory("<subscription-id>", cred, nil)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}
	res, err := clientFactory.NewZonesClient().Get(ctx, "rg1", "zone1", nil)
	if err != nil {
		log.Fatalf("failed to finish the request: %v", err)
	}
	// You could use response here. We use blank identifier for just demo purposes.
	_ = res
	// If the HTTP response code is 200 as defined in example definition, your response structure would look as follows. Please pay attention that all the values in the output are fake values for just demo purposes.
	// res.Zone = armdns.Zone{
	// 	Name: to.Ptr("zone1"),
	// 	Type: to.Ptr("Microsoft.Network/dnsZones"),
	// 	ID: to.Ptr("/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/dnsZones/zone1"),
	// 	Location: to.Ptr("global"),
	// 	Tags: map[string]*string{
	// 		"key1": to.Ptr("value1"),
	// 	},
	// 	Etag: to.Ptr("00000000-0000-0000-0000-000000000000"),
	// 	Properties: &armdns.ZoneProperties{
	// 		MaxNumberOfRecordSets: to.Ptr[int64](5000),
	// 		NameServers: []*string{
	// 			to.Ptr("ns1-01.azure-dns.com"),
	// 			to.Ptr("ns2-01.azure-dns.net"),
	// 			to.Ptr("ns3-01.azure-dns.org"),
	// 			to.Ptr("ns4-01.azure-dns.info")},
	// 			NumberOfRecordSets: to.Ptr[int64](2),
	// 		},
	// 	}
}

// Generated from example definition: https://github.com/Azure/azure-rest-api-specs/blob/987a8f38ab2a8359d085e149be042267a9ecc66f/specification/dns/resource-manager/Microsoft.Network/preview/2023-07-01-preview/examples/PatchZone.json
func ExampleZonesClient_Update() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	clientFactory, err := armdns.NewClientFactory("<subscription-id>", cred, nil)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}
	res, err := clientFactory.NewZonesClient().Update(ctx, "rg1", "zone1", armdns.ZoneUpdate{
		Tags: map[string]*string{
			"key2": to.Ptr("value2"),
		},
	}, &armdns.ZonesClientUpdateOptions{IfMatch: nil})
	if err != nil {
		log.Fatalf("failed to finish the request: %v", err)
	}
	// You could use response here. We use blank identifier for just demo purposes.
	_ = res
	// If the HTTP response code is 200 as defined in example definition, your response structure would look as follows. Please pay attention that all the values in the output are fake values for just demo purposes.
	// res.Zone = armdns.Zone{
	// 	Name: to.Ptr("zone1"),
	// 	Type: to.Ptr("Microsoft.Network/dnsZones"),
	// 	ID: to.Ptr("/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/dnsZones/zone1"),
	// 	Location: to.Ptr("global"),
	// 	Tags: map[string]*string{
	// 		"key2": to.Ptr("value2"),
	// 	},
	// 	Etag: to.Ptr("00000000-0000-0000-0000-000000000000"),
	// 	Properties: &armdns.ZoneProperties{
	// 		MaxNumberOfRecordSets: to.Ptr[int64](5000),
	// 		NameServers: []*string{
	// 			to.Ptr("ns1-01.azure-dns.com"),
	// 			to.Ptr("ns2-01.azure-dns.net"),
	// 			to.Ptr("ns3-01.azure-dns.org"),
	// 			to.Ptr("ns4-01.azure-dns.info")},
	// 			NumberOfRecordSets: to.Ptr[int64](2),
	// 		},
	// 	}
}

// Generated from example definition: https://github.com/Azure/azure-rest-api-specs/blob/987a8f38ab2a8359d085e149be042267a9ecc66f/specification/dns/resource-manager/Microsoft.Network/preview/2023-07-01-preview/examples/ListZonesByResourceGroup.json
func ExampleZonesClient_NewListByResourceGroupPager() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	clientFactory, err := armdns.NewClientFactory("<subscription-id>", cred, nil)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}
	pager := clientFactory.NewZonesClient().NewListByResourceGroupPager("rg1", &armdns.ZonesClientListByResourceGroupOptions{Top: nil})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			log.Fatalf("failed to advance page: %v", err)
		}
		for _, v := range page.Value {
			// You could use page here. We use blank identifier for just demo purposes.
			_ = v
		}
		// If the HTTP response code is 200 as defined in example definition, your page structure would look as follows. Please pay attention that all the values in the output are fake values for just demo purposes.
		// page.ZoneListResult = armdns.ZoneListResult{
		// 	Value: []*armdns.Zone{
		// 		{
		// 			Name: to.Ptr("zone1"),
		// 			Type: to.Ptr("Microsoft.Network/dnsZones"),
		// 			ID: to.Ptr("/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/dnsZones/zone1"),
		// 			Location: to.Ptr("global"),
		// 			Tags: map[string]*string{
		// 				"key1": to.Ptr("value1"),
		// 			},
		// 			Etag: to.Ptr("00000000-0000-0000-0000-000000000000"),
		// 			Properties: &armdns.ZoneProperties{
		// 				MaxNumberOfRecordSets: to.Ptr[int64](5000),
		// 				NameServers: []*string{
		// 					to.Ptr("ns1-01.azure-dns.com"),
		// 					to.Ptr("ns2-01.azure-dns.net"),
		// 					to.Ptr("ns3-01.azure-dns.org"),
		// 					to.Ptr("ns4-01.azure-dns.info")},
		// 					NumberOfRecordSets: to.Ptr[int64](2),
		// 				},
		// 			},
		// 			{
		// 				Name: to.Ptr("zone2"),
		// 				Type: to.Ptr("Microsoft.Network/dnsZones"),
		// 				ID: to.Ptr("/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/dnsZones/zone2"),
		// 				Location: to.Ptr("global"),
		// 				Etag: to.Ptr("00000000-0000-0000-0000-000000000000"),
		// 				Properties: &armdns.ZoneProperties{
		// 					MaxNumberOfRecordSets: to.Ptr[int64](5000),
		// 					NameServers: []*string{
		// 						to.Ptr("ns1-02.azure-dns.com"),
		// 						to.Ptr("ns2-02.azure-dns.net"),
		// 						to.Ptr("ns3-02.azure-dns.org"),
		// 						to.Ptr("ns4-02.azure-dns.info")},
		// 						NumberOfRecordSets: to.Ptr[int64](300),
		// 					},
		// 			}},
		// 		}
	}
}

// Generated from example definition: https://github.com/Azure/azure-rest-api-specs/blob/987a8f38ab2a8359d085e149be042267a9ecc66f/specification/dns/resource-manager/Microsoft.Network/preview/2023-07-01-preview/examples/ListZonesBySubscription.json
func ExampleZonesClient_NewListPager() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	clientFactory, err := armdns.NewClientFactory("<subscription-id>", cred, nil)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}
	pager := clientFactory.NewZonesClient().NewListPager(&armdns.ZonesClientListOptions{Top: nil})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			log.Fatalf("failed to advance page: %v", err)
		}
		for _, v := range page.Value {
			// You could use page here. We use blank identifier for just demo purposes.
			_ = v
		}
		// If the HTTP response code is 200 as defined in example definition, your page structure would look as follows. Please pay attention that all the values in the output are fake values for just demo purposes.
		// page.ZoneListResult = armdns.ZoneListResult{
		// 	Value: []*armdns.Zone{
		// 		{
		// 			Name: to.Ptr("zone1"),
		// 			Type: to.Ptr("Microsoft.Network/dnsZones"),
		// 			ID: to.Ptr("/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/dnsZones/zone1"),
		// 			Location: to.Ptr("global"),
		// 			Tags: map[string]*string{
		// 				"key1": to.Ptr("value1"),
		// 			},
		// 			Etag: to.Ptr("00000000-0000-0000-0000-000000000000"),
		// 			Properties: &armdns.ZoneProperties{
		// 				MaxNumberOfRecordSets: to.Ptr[int64](5000),
		// 				NameServers: []*string{
		// 					to.Ptr("ns1-01.azure-dns.com"),
		// 					to.Ptr("ns2-01.azure-dns.net"),
		// 					to.Ptr("ns3-01.azure-dns.org"),
		// 					to.Ptr("ns4-01.azure-dns.info")},
		// 					NumberOfRecordSets: to.Ptr[int64](2),
		// 				},
		// 			},
		// 			{
		// 				Name: to.Ptr("zone2"),
		// 				Type: to.Ptr("Microsoft.Network/dnsZones"),
		// 				ID: to.Ptr("/subscriptions/subid/resourceGroups/rg2/providers/Microsoft.Network/dnsZones/zone2"),
		// 				Location: to.Ptr("global"),
		// 				Etag: to.Ptr("00000000-0000-0000-0000-000000000000"),
		// 				Properties: &armdns.ZoneProperties{
		// 					MaxNumberOfRecordSets: to.Ptr[int64](5000),
		// 					NameServers: []*string{
		// 						to.Ptr("ns1-02.azure-dns.com"),
		// 						to.Ptr("ns2-02.azure-dns.net"),
		// 						to.Ptr("ns3-02.azure-dns.org"),
		// 						to.Ptr("ns4-02.azure-dns.info")},
		// 						NumberOfRecordSets: to.Ptr[int64](300),
		// 					},
		// 			}},
		// 		}
	}
}
