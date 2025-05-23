//go:build go1.18
// +build go1.18

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.
// DO NOT EDIT.

package armkeyvault_test

import (
	"context"
	"log"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
)

// Generated from example definition: https://github.com/Azure/azure-rest-api-specs/blob/ee1eec42dcc710ff88db2d1bf574b2f9afe3d654/specification/keyvault/resource-manager/Microsoft.KeyVault/stable/2024-11-01/examples/listOperations.json
func ExampleOperationsClient_NewListPager() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	clientFactory, err := armkeyvault.NewClientFactory("<subscription-id>", cred, nil)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}
	pager := clientFactory.NewOperationsClient().NewListPager(nil)
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
		// page.OperationListResult = armkeyvault.OperationListResult{
		// 	Value: []*armkeyvault.Operation{
		// 		{
		// 			Name: to.Ptr("Microsoft.KeyVault/vaults/read"),
		// 			Display: &armkeyvault.OperationDisplay{
		// 				Description: to.Ptr("View the properties of a key vault"),
		// 				Operation: to.Ptr("View Key Vault"),
		// 				Provider: to.Ptr("Microsoft Key Vault"),
		// 				Resource: to.Ptr("Key Vault"),
		// 			},
		// 			IsDataAction: to.Ptr(false),
		// 		},
		// 		{
		// 			Name: to.Ptr("Microsoft.KeyVault/vaults/write"),
		// 			Display: &armkeyvault.OperationDisplay{
		// 				Description: to.Ptr("Create a new key vault or update the properties of an existing key vault"),
		// 				Operation: to.Ptr("Update Key Vault"),
		// 				Provider: to.Ptr("Microsoft Key Vault"),
		// 				Resource: to.Ptr("Key Vault"),
		// 			},
		// 			IsDataAction: to.Ptr(false),
		// 		},
		// 		{
		// 			Name: to.Ptr("Microsoft.KeyVault/vaults/delete"),
		// 			Display: &armkeyvault.OperationDisplay{
		// 				Description: to.Ptr("Delete a key vault"),
		// 				Operation: to.Ptr("Delete Key Vault"),
		// 				Provider: to.Ptr("Microsoft Key Vault"),
		// 				Resource: to.Ptr("Key Vault"),
		// 			},
		// 			IsDataAction: to.Ptr(false),
		// 		},
		// 		{
		// 			Name: to.Ptr("Microsoft.KeyVault/vaults/deploy/action"),
		// 			Display: &armkeyvault.OperationDisplay{
		// 				Description: to.Ptr("Enables access to secrets in a key vault when deploying Azure resources"),
		// 				Operation: to.Ptr("Use Vault for Azure Deployments"),
		// 				Provider: to.Ptr("Microsoft Key Vault"),
		// 				Resource: to.Ptr("Key Vault"),
		// 			},
		// 			IsDataAction: to.Ptr(false),
		// 		},
		// 		{
		// 			Name: to.Ptr("Microsoft.KeyVault/vaults/secrets/read"),
		// 			Display: &armkeyvault.OperationDisplay{
		// 				Description: to.Ptr("View the properties of a secret, but not its value"),
		// 				Operation: to.Ptr("View Secret Properties"),
		// 				Provider: to.Ptr("Microsoft Key Vault"),
		// 				Resource: to.Ptr("Secret"),
		// 			},
		// 			IsDataAction: to.Ptr(false),
		// 		},
		// 		{
		// 			Name: to.Ptr("Microsoft.KeyVault/vaults/secrets/write"),
		// 			Display: &armkeyvault.OperationDisplay{
		// 				Description: to.Ptr("Create a new secret or update the value of an existing secret"),
		// 				Operation: to.Ptr("Update Secret"),
		// 				Provider: to.Ptr("Microsoft Key Vault"),
		// 				Resource: to.Ptr("Secret"),
		// 			},
		// 			IsDataAction: to.Ptr(false),
		// 		},
		// 		{
		// 			Name: to.Ptr("Microsoft.KeyVault/vaults/accessPolicies/write"),
		// 			Display: &armkeyvault.OperationDisplay{
		// 				Description: to.Ptr("Update an existing access policy by merging or replacing, or add a new access policy to a vault."),
		// 				Operation: to.Ptr("Update Access Policy"),
		// 				Provider: to.Ptr("Microsoft Key Vault"),
		// 				Resource: to.Ptr("Access Policy"),
		// 			},
		// 			IsDataAction: to.Ptr(false),
		// 		},
		// 		{
		// 			Name: to.Ptr("Microsoft.KeyVault/vaults/providers/Microsoft.Insights/logDefinitions/read"),
		// 			Display: &armkeyvault.OperationDisplay{
		// 				Description: to.Ptr("Gets the available logs for a key vault"),
		// 				Operation: to.Ptr("Read log definition"),
		// 				Provider: to.Ptr("Microsoft Key Vault"),
		// 				Resource: to.Ptr("Key Vault Log Definition"),
		// 			},
		// 			IsDataAction: to.Ptr(false),
		// 			Origin: to.Ptr("system"),
		// 			OperationProperties: &armkeyvault.OperationProperties{
		// 				ServiceSpecification: &armkeyvault.ServiceSpecification{
		// 					LogSpecifications: []*armkeyvault.LogSpecification{
		// 						{
		// 							Name: to.Ptr("AuditEvent"),
		// 							BlobDuration: to.Ptr("PT1H"),
		// 							DisplayName: to.Ptr("Audit Logs"),
		// 					}},
		// 					MetricSpecifications: []*armkeyvault.MetricSpecification{
		// 						{
		// 							Name: to.Ptr("ServiceApiHit"),
		// 							AggregationType: to.Ptr(""),
		// 							Dimensions: []*armkeyvault.DimensionProperties{
		// 								{
		// 									Name: to.Ptr("ActivityType"),
		// 									DisplayName: to.Ptr(""),
		// 									ToBeExportedForShoebox: to.Ptr(true),
		// 								},
		// 								{
		// 									Name: to.Ptr("ActivityName"),
		// 									DisplayName: to.Ptr(""),
		// 									ToBeExportedForShoebox: to.Ptr(true),
		// 							}},
		// 							DisplayDescription: to.Ptr(""),
		// 							DisplayName: to.Ptr(""),
		// 							FillGapWithZero: to.Ptr(false),
		// 							InternalMetricName: to.Ptr("AuditEvent"),
		// 							LockAggregationType: to.Ptr(""),
		// 							SupportedAggregationTypes: []*string{
		// 								to.Ptr("")},
		// 								SupportedTimeGrainTypes: []*string{
		// 									to.Ptr("")},
		// 									Unit: to.Ptr(""),
		// 							}},
		// 						},
		// 					},
		// 				},
		// 				{
		// 					Name: to.Ptr("Microsoft.KeyVault/vaults/providers/Microsoft.Insights/diagnosticSettings/Read"),
		// 					Display: &armkeyvault.OperationDisplay{
		// 						Description: to.Ptr("Gets the diagnostic setting for the resource"),
		// 						Operation: to.Ptr("Read diagnostic setting"),
		// 						Provider: to.Ptr("Microsoft Key Vault"),
		// 						Resource: to.Ptr("Key Vault Diagnostic Settings"),
		// 					},
		// 					IsDataAction: to.Ptr(false),
		// 					Origin: to.Ptr("system"),
		// 				},
		// 				{
		// 					Name: to.Ptr("Microsoft.KeyVault/vaults/providers/Microsoft.Insights/diagnosticSettings/Write"),
		// 					Display: &armkeyvault.OperationDisplay{
		// 						Description: to.Ptr("Creates or updates the diagnostic setting for the resource"),
		// 						Operation: to.Ptr("Write diagnostic setting"),
		// 						Provider: to.Ptr("Microsoft Key Vault"),
		// 						Resource: to.Ptr("Key Vault Diagnostic Settings"),
		// 					},
		// 					IsDataAction: to.Ptr(false),
		// 					Origin: to.Ptr("system"),
		// 				},
		// 				{
		// 					Name: to.Ptr("Microsoft.KeyVault/register/action"),
		// 					Display: &armkeyvault.OperationDisplay{
		// 						Description: to.Ptr("Registers a subscription"),
		// 						Operation: to.Ptr("Register Subscription"),
		// 						Provider: to.Ptr("Microsoft Key Vault"),
		// 						Resource: to.Ptr("Subscription"),
		// 					},
		// 					IsDataAction: to.Ptr(false),
		// 				},
		// 				{
		// 					Name: to.Ptr("Microsoft.KeyVault/unregister/action"),
		// 					Display: &armkeyvault.OperationDisplay{
		// 						Description: to.Ptr("Unregisters a subscription"),
		// 						Operation: to.Ptr("Unregister Subscription"),
		// 						Provider: to.Ptr("Microsoft Key Vault"),
		// 						Resource: to.Ptr("Subscription"),
		// 					},
		// 					IsDataAction: to.Ptr(false),
		// 				},
		// 				{
		// 					Name: to.Ptr("Microsoft.KeyVault/operations/read"),
		// 					Display: &armkeyvault.OperationDisplay{
		// 						Description: to.Ptr("Lists operations available on Microsoft.KeyVault resource provider"),
		// 						Operation: to.Ptr("Available Key Vault Operations"),
		// 						Provider: to.Ptr("Microsoft Key Vault"),
		// 						Resource: to.Ptr("Operations"),
		// 					},
		// 					IsDataAction: to.Ptr(false),
		// 				},
		// 				{
		// 					Name: to.Ptr("Microsoft.KeyVault/checkNameAvailability/read"),
		// 					Display: &armkeyvault.OperationDisplay{
		// 						Description: to.Ptr("Checks that a key vault name is valid and is not in use"),
		// 						Operation: to.Ptr("Check Name Availability"),
		// 						Provider: to.Ptr("Microsoft Key Vault"),
		// 						Resource: to.Ptr("Name Availability"),
		// 					},
		// 					IsDataAction: to.Ptr(false),
		// 				},
		// 				{
		// 					Name: to.Ptr("Microsoft.KeyVault/deletedVaults/read"),
		// 					Display: &armkeyvault.OperationDisplay{
		// 						Description: to.Ptr("View the properties of soft deleted key vaults"),
		// 						Operation: to.Ptr("View Soft Deleted Vaults"),
		// 						Provider: to.Ptr("Microsoft Key Vault"),
		// 						Resource: to.Ptr("Soft Deleted Key Vault"),
		// 					},
		// 					IsDataAction: to.Ptr(false),
		// 				},
		// 				{
		// 					Name: to.Ptr("Microsoft.KeyVault/locations/deletedVaults/read"),
		// 					Display: &armkeyvault.OperationDisplay{
		// 						Description: to.Ptr("View the properties of a soft deleted key vault"),
		// 						Operation: to.Ptr("View Soft Deleted Key Vault"),
		// 						Provider: to.Ptr("Microsoft Key Vault"),
		// 						Resource: to.Ptr("Soft Deleted Key Vault"),
		// 					},
		// 					IsDataAction: to.Ptr(false),
		// 				},
		// 				{
		// 					Name: to.Ptr("Microsoft.KeyVault/locations/deletedVaults/purge/action"),
		// 					Display: &armkeyvault.OperationDisplay{
		// 						Description: to.Ptr("Purge a soft deleted key vault"),
		// 						Operation: to.Ptr("Purge Soft Deleted Key Vault"),
		// 						Provider: to.Ptr("Microsoft Key Vault"),
		// 						Resource: to.Ptr("Soft Deleted Key Vault"),
		// 					},
		// 					IsDataAction: to.Ptr(false),
		// 				},
		// 				{
		// 					Name: to.Ptr("Microsoft.KeyVault/locations/operationResults/read"),
		// 					Display: &armkeyvault.OperationDisplay{
		// 						Description: to.Ptr("Check the result of a long run operation"),
		// 						Operation: to.Ptr("Check Operation Result"),
		// 						Provider: to.Ptr("Microsoft Key Vault"),
		// 						Resource: to.Ptr("Long Run Operation Result"),
		// 					},
		// 					IsDataAction: to.Ptr(false),
		// 				},
		// 				{
		// 					Name: to.Ptr("Microsoft.KeyVault/hsmPools/read"),
		// 					Display: &armkeyvault.OperationDisplay{
		// 						Description: to.Ptr("View the properties of an HSM pool"),
		// 						Operation: to.Ptr("View HSM pool"),
		// 						Provider: to.Ptr("Microsoft Key Vault"),
		// 						Resource: to.Ptr("HSM pool"),
		// 					},
		// 					IsDataAction: to.Ptr(false),
		// 				},
		// 				{
		// 					Name: to.Ptr("Microsoft.KeyVault/hsmPools/write"),
		// 					Display: &armkeyvault.OperationDisplay{
		// 						Description: to.Ptr("Create a new HSM pool of update the properties of an existing HSM pool"),
		// 						Operation: to.Ptr("Create or Update HSM pool"),
		// 						Provider: to.Ptr("Microsoft Key Vault"),
		// 						Resource: to.Ptr("HSM pool"),
		// 					},
		// 					IsDataAction: to.Ptr(false),
		// 				},
		// 				{
		// 					Name: to.Ptr("Microsoft.KeyVault/hsmPools/delete"),
		// 					Display: &armkeyvault.OperationDisplay{
		// 						Description: to.Ptr("Delete an HSM pool"),
		// 						Operation: to.Ptr("Delete HSM pool"),
		// 						Provider: to.Ptr("Microsoft Key Vault"),
		// 						Resource: to.Ptr("HSM pool"),
		// 					},
		// 					IsDataAction: to.Ptr(false),
		// 				},
		// 				{
		// 					Name: to.Ptr("Microsoft.KeyVault/hsmPools/joinVault/action"),
		// 					Display: &armkeyvault.OperationDisplay{
		// 						Description: to.Ptr("Join a key vault to an HSM pool"),
		// 						Operation: to.Ptr("Join KeyVault to HSM pool"),
		// 						Provider: to.Ptr("Microsoft Key Vault"),
		// 						Resource: to.Ptr("HSM pool"),
		// 					},
		// 					IsDataAction: to.Ptr(false),
		// 				},
		// 				{
		// 					Name: to.Ptr("Microsoft.KeyVault/managedHSMs/read"),
		// 					Display: &armkeyvault.OperationDisplay{
		// 						Description: to.Ptr("View the properties of a Managed HSM"),
		// 						Operation: to.Ptr("View Managed HSM"),
		// 						Provider: to.Ptr("Microsoft Key Vault"),
		// 						Resource: to.Ptr("Managed HSM"),
		// 					},
		// 					IsDataAction: to.Ptr(false),
		// 				},
		// 				{
		// 					Name: to.Ptr("Microsoft.KeyVault/managedHSMs/write"),
		// 					Display: &armkeyvault.OperationDisplay{
		// 						Description: to.Ptr("Create a new Managed HSM of update the properties of an existing Managed HSM"),
		// 						Operation: to.Ptr("Create or Update Managed HSM"),
		// 						Provider: to.Ptr("Microsoft Key Vault"),
		// 						Resource: to.Ptr("Managed HSM"),
		// 					},
		// 					IsDataAction: to.Ptr(false),
		// 				},
		// 				{
		// 					Name: to.Ptr("Microsoft.KeyVault/managedHSMs/delete"),
		// 					Display: &armkeyvault.OperationDisplay{
		// 						Description: to.Ptr("Delete a Managed HSM"),
		// 						Operation: to.Ptr("Delete Managed HSM"),
		// 						Provider: to.Ptr("Microsoft Key Vault"),
		// 						Resource: to.Ptr("Managed HSM"),
		// 					},
		// 					IsDataAction: to.Ptr(false),
		// 				},
		// 				{
		// 					Name: to.Ptr("Microsoft.KeyVault/vaults/providers/Microsoft.Insights/metricDefinitions/read"),
		// 					Display: &armkeyvault.OperationDisplay{
		// 						Description: to.Ptr("Gets the available metrics for a key vault"),
		// 						Operation: to.Ptr("Read metric definition"),
		// 						Provider: to.Ptr("Microsoft Key Vault"),
		// 						Resource: to.Ptr("Key Vault Metric Definition"),
		// 					},
		// 					IsDataAction: to.Ptr(false),
		// 					Origin: to.Ptr("system"),
		// 					OperationProperties: &armkeyvault.OperationProperties{
		// 						ServiceSpecification: &armkeyvault.ServiceSpecification{
		// 						},
		// 					},
		// 				},
		// 				{
		// 					Name: to.Ptr("Microsoft.KeyVault/locations/deleteVirtualNetworkOrSubnets/action"),
		// 					Display: &armkeyvault.OperationDisplay{
		// 						Description: to.Ptr("Notifies Microsoft.KeyVault that a virtual network or subnet is being deleted"),
		// 						Operation: to.Ptr("Modify Network ACLs containing the deleted Vitual Network or Subnet "),
		// 						Provider: to.Ptr("Microsoft Key Vault"),
		// 						Resource: to.Ptr("Location"),
		// 					},
		// 					IsDataAction: to.Ptr(false),
		// 					Origin: to.Ptr("system"),
		// 			}},
		// 		}
	}
}
