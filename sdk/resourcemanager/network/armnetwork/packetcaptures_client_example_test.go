//go:build go1.18
// +build go1.18

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.
// DO NOT EDIT.

package armnetwork_test

import (
	"context"
	"log"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
)

// Generated from example definition: https://github.com/Azure/azure-rest-api-specs/blob/ab04533261eff228f28e08900445d0edef3eb70c/specification/network/resource-manager/Microsoft.Network/stable/2024-05-01/examples/NetworkWatcherPacketCaptureCreate.json
func ExamplePacketCapturesClient_BeginCreate() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	clientFactory, err := armnetwork.NewClientFactory("<subscription-id>", cred, nil)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}
	poller, err := clientFactory.NewPacketCapturesClient().BeginCreate(ctx, "rg1", "nw1", "pc1", armnetwork.PacketCapture{
		Properties: &armnetwork.PacketCaptureParameters{
			BytesToCapturePerPacket: to.Ptr[int64](10000),
			Filters: []*armnetwork.PacketCaptureFilter{
				{
					LocalIPAddress: to.Ptr("10.0.0.4"),
					LocalPort:      to.Ptr("80"),
					Protocol:       to.Ptr(armnetwork.PcProtocolTCP),
				}},
			StorageLocation: &armnetwork.PacketCaptureStorageLocation{
				FilePath:    to.Ptr("D:\\capture\\pc1.cap"),
				StorageID:   to.Ptr("/subscriptions/subid/resourceGroups/rg2/providers/Microsoft.Storage/storageAccounts/pcstore"),
				StoragePath: to.Ptr("https://mytestaccountname.blob.core.windows.net/capture/pc1.cap"),
			},
			Target:               to.Ptr("/subscriptions/subid/resourceGroups/rg2/providers/Microsoft.Compute/virtualMachines/vm1"),
			TimeLimitInSeconds:   to.Ptr[int32](100),
			TotalBytesPerSession: to.Ptr[int64](100000),
		},
	}, nil)
	if err != nil {
		log.Fatalf("failed to finish the request: %v", err)
	}
	_, err = poller.PollUntilDone(ctx, nil)
	if err != nil {
		log.Fatalf("failed to pull the result: %v", err)
	}
}

// Generated from example definition: https://github.com/Azure/azure-rest-api-specs/blob/ab04533261eff228f28e08900445d0edef3eb70c/specification/network/resource-manager/Microsoft.Network/stable/2024-05-01/examples/NetworkWatcherPacketCaptureGet.json
func ExamplePacketCapturesClient_Get() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	clientFactory, err := armnetwork.NewClientFactory("<subscription-id>", cred, nil)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}
	res, err := clientFactory.NewPacketCapturesClient().Get(ctx, "rg1", "nw1", "pc1", nil)
	if err != nil {
		log.Fatalf("failed to finish the request: %v", err)
	}
	// You could use response here. We use blank identifier for just demo purposes.
	_ = res
	// If the HTTP response code is 200 as defined in example definition, your response structure would look as follows. Please pay attention that all the values in the output are fake values for just demo purposes.
	// res.PacketCaptureResult = armnetwork.PacketCaptureResult{
	// 	Name: to.Ptr("pc1"),
	// 	Etag: to.Ptr("W/\"00000000-0000-0000-0000-000000000000\""),
	// 	ID: to.Ptr("/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/networkWatchers/nw1/packetCaptures/pc1"),
	// 	Properties: &armnetwork.PacketCaptureResultProperties{
	// 		BytesToCapturePerPacket: to.Ptr[int64](10000),
	// 		Filters: []*armnetwork.PacketCaptureFilter{
	// 			{
	// 				LocalIPAddress: to.Ptr("10.0.0.4"),
	// 				LocalPort: to.Ptr("80"),
	// 				Protocol: to.Ptr(armnetwork.PcProtocolTCP),
	// 		}},
	// 		StorageLocation: &armnetwork.PacketCaptureStorageLocation{
	// 			FilePath: to.Ptr("D:\\capture\\pc1.cap"),
	// 			StorageID: to.Ptr("/subscriptions/subid/resourceGroups/rg2/providers/Microsoft.Storage/storageAccounts/pcstore"),
	// 			StoragePath: to.Ptr("https://mytestaccountname.blob.core.windows.net/capture/pc1.cap"),
	// 		},
	// 		Target: to.Ptr("/subscriptions/subid/resourceGroups/rg2/providers/Microsoft.Compute/virtualMachines/vm1"),
	// 		TimeLimitInSeconds: to.Ptr[int32](100),
	// 		TotalBytesPerSession: to.Ptr[int64](100000),
	// 		ProvisioningState: to.Ptr(armnetwork.ProvisioningStateSucceeded),
	// 	},
	// }
}

// Generated from example definition: https://github.com/Azure/azure-rest-api-specs/blob/ab04533261eff228f28e08900445d0edef3eb70c/specification/network/resource-manager/Microsoft.Network/stable/2024-05-01/examples/NetworkWatcherPacketCaptureDelete.json
func ExamplePacketCapturesClient_BeginDelete() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	clientFactory, err := armnetwork.NewClientFactory("<subscription-id>", cred, nil)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}
	poller, err := clientFactory.NewPacketCapturesClient().BeginDelete(ctx, "rg1", "nw1", "pc1", nil)
	if err != nil {
		log.Fatalf("failed to finish the request: %v", err)
	}
	_, err = poller.PollUntilDone(ctx, nil)
	if err != nil {
		log.Fatalf("failed to pull the result: %v", err)
	}
}

// Generated from example definition: https://github.com/Azure/azure-rest-api-specs/blob/ab04533261eff228f28e08900445d0edef3eb70c/specification/network/resource-manager/Microsoft.Network/stable/2024-05-01/examples/NetworkWatcherPacketCaptureStop.json
func ExamplePacketCapturesClient_BeginStop() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	clientFactory, err := armnetwork.NewClientFactory("<subscription-id>", cred, nil)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}
	poller, err := clientFactory.NewPacketCapturesClient().BeginStop(ctx, "rg1", "nw1", "pc1", nil)
	if err != nil {
		log.Fatalf("failed to finish the request: %v", err)
	}
	_, err = poller.PollUntilDone(ctx, nil)
	if err != nil {
		log.Fatalf("failed to pull the result: %v", err)
	}
}

// Generated from example definition: https://github.com/Azure/azure-rest-api-specs/blob/ab04533261eff228f28e08900445d0edef3eb70c/specification/network/resource-manager/Microsoft.Network/stable/2024-05-01/examples/NetworkWatcherPacketCaptureQueryStatus.json
func ExamplePacketCapturesClient_BeginGetStatus() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	clientFactory, err := armnetwork.NewClientFactory("<subscription-id>", cred, nil)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}
	poller, err := clientFactory.NewPacketCapturesClient().BeginGetStatus(ctx, "rg1", "nw1", "pc1", nil)
	if err != nil {
		log.Fatalf("failed to finish the request: %v", err)
	}
	res, err := poller.PollUntilDone(ctx, nil)
	if err != nil {
		log.Fatalf("failed to pull the result: %v", err)
	}
	// You could use response here. We use blank identifier for just demo purposes.
	_ = res
	// If the HTTP response code is 200 as defined in example definition, your response structure would look as follows. Please pay attention that all the values in the output are fake values for just demo purposes.
	// res.PacketCaptureQueryStatusResult = armnetwork.PacketCaptureQueryStatusResult{
	// 	Name: to.Ptr("pc1"),
	// 	CaptureStartTime: to.Ptr(func() time.Time { t, _ := time.Parse(time.RFC3339Nano, "2016-09-07T12:35:24.000Z"); return t}()),
	// 	ID: to.Ptr("/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/networkWatchers/nw1/packetCaptures/pc1"),
	// 	PacketCaptureError: []*armnetwork.PcError{
	// 	},
	// 	PacketCaptureStatus: to.Ptr(armnetwork.PcStatusStopped),
	// 	StopReason: to.Ptr("TimeExceeded"),
	// }
}

// Generated from example definition: https://github.com/Azure/azure-rest-api-specs/blob/ab04533261eff228f28e08900445d0edef3eb70c/specification/network/resource-manager/Microsoft.Network/stable/2024-05-01/examples/NetworkWatcherPacketCapturesList.json
func ExamplePacketCapturesClient_NewListPager() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	clientFactory, err := armnetwork.NewClientFactory("<subscription-id>", cred, nil)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}
	pager := clientFactory.NewPacketCapturesClient().NewListPager("rg1", "nw1", nil)
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
		// page.PacketCaptureListResult = armnetwork.PacketCaptureListResult{
		// 	Value: []*armnetwork.PacketCaptureResult{
		// 		{
		// 			Name: to.Ptr("pc1"),
		// 			Etag: to.Ptr("W/\"00000000-0000-0000-0000-000000000000\""),
		// 			ID: to.Ptr("/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/networkWatchers/nw1/packetCaptures/pc1"),
		// 			Properties: &armnetwork.PacketCaptureResultProperties{
		// 				BytesToCapturePerPacket: to.Ptr[int64](10000),
		// 				Filters: []*armnetwork.PacketCaptureFilter{
		// 					{
		// 						LocalIPAddress: to.Ptr("10.0.0.4"),
		// 						LocalPort: to.Ptr("80"),
		// 						Protocol: to.Ptr(armnetwork.PcProtocolTCP),
		// 				}},
		// 				StorageLocation: &armnetwork.PacketCaptureStorageLocation{
		// 					FilePath: to.Ptr("D:\\capture\\pc1.cap"),
		// 					StorageID: to.Ptr("/subscriptions/subid/resourceGroups/rg2/providers/Microsoft.Storage/storageAccounts/pcstore"),
		// 					StoragePath: to.Ptr("https://mytestaccountname.blob.core.windows.net/capture/pc1.cap"),
		// 				},
		// 				Target: to.Ptr("/subscriptions/subid/resourceGroups/rg2/providers/Microsoft.Compute/virtualMachines/vm1"),
		// 				TimeLimitInSeconds: to.Ptr[int32](100),
		// 				TotalBytesPerSession: to.Ptr[int64](100000),
		// 				ProvisioningState: to.Ptr(armnetwork.ProvisioningStateSucceeded),
		// 			},
		// 		},
		// 		{
		// 			Name: to.Ptr("pc2"),
		// 			Etag: to.Ptr("W/\"00000000-0000-0000-0000-000000000000\""),
		// 			ID: to.Ptr("/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/networkWatchers/nw1/packetCaptures/pc2"),
		// 			Properties: &armnetwork.PacketCaptureResultProperties{
		// 				BytesToCapturePerPacket: to.Ptr[int64](10000),
		// 				Filters: []*armnetwork.PacketCaptureFilter{
		// 				},
		// 				StorageLocation: &armnetwork.PacketCaptureStorageLocation{
		// 					FilePath: to.Ptr("D:\\capture\\pc2.cap"),
		// 					StorageID: to.Ptr("/subscriptions/subid/resourceGroups/rg2/providers/Microsoft.Storage/storageAccounts/pcstore"),
		// 					StoragePath: to.Ptr("https://mytestaccountname.blob.core.windows.net/capture/pc2.cap"),
		// 				},
		// 				Target: to.Ptr("/subscriptions/subid/resourceGroups/rg2/providers/Microsoft.Compute/virtualMachines/vm1"),
		// 				TimeLimitInSeconds: to.Ptr[int32](100),
		// 				TotalBytesPerSession: to.Ptr[int64](100000),
		// 				ProvisioningState: to.Ptr(armnetwork.ProvisioningStateSucceeded),
		// 			},
		// 	}},
		// }
	}
}
