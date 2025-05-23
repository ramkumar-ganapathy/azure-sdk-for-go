// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator. DO NOT EDIT.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armapplicationinsights

import (
	"context"
	"errors"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"net/http"
	"net/url"
	"strings"
)

// WorkbookTemplatesClient contains the methods for the WorkbookTemplates group.
// Don't use this type directly, use NewWorkbookTemplatesClient() instead.
type WorkbookTemplatesClient struct {
	internal       *arm.Client
	subscriptionID string
}

// NewWorkbookTemplatesClient creates a new instance of WorkbookTemplatesClient with the specified values.
//   - subscriptionID - The ID of the target subscription.
//   - credential - used to authorize requests. Usually a credential from azidentity.
//   - options - pass nil to accept the default values.
func NewWorkbookTemplatesClient(subscriptionID string, credential azcore.TokenCredential, options *arm.ClientOptions) (*WorkbookTemplatesClient, error) {
	cl, err := arm.NewClient(moduleName, moduleVersion, credential, options)
	if err != nil {
		return nil, err
	}
	client := &WorkbookTemplatesClient{
		subscriptionID: subscriptionID,
		internal:       cl,
	}
	return client, nil
}

// CreateOrUpdate - Create a new workbook template.
// If the operation fails it returns an *azcore.ResponseError type.
//
// Generated from API version 2020-11-20
//   - resourceGroupName - The name of the resource group. The name is case insensitive.
//   - resourceName - The name of the Application Insights component resource.
//   - workbookTemplateProperties - Properties that need to be specified to create a new workbook.
//   - options - WorkbookTemplatesClientCreateOrUpdateOptions contains the optional parameters for the WorkbookTemplatesClient.CreateOrUpdate
//     method.
func (client *WorkbookTemplatesClient) CreateOrUpdate(ctx context.Context, resourceGroupName string, resourceName string, workbookTemplateProperties WorkbookTemplate, options *WorkbookTemplatesClientCreateOrUpdateOptions) (WorkbookTemplatesClientCreateOrUpdateResponse, error) {
	var err error
	const operationName = "WorkbookTemplatesClient.CreateOrUpdate"
	ctx = context.WithValue(ctx, runtime.CtxAPINameKey{}, operationName)
	ctx, endSpan := runtime.StartSpan(ctx, operationName, client.internal.Tracer(), nil)
	defer func() { endSpan(err) }()
	req, err := client.createOrUpdateCreateRequest(ctx, resourceGroupName, resourceName, workbookTemplateProperties, options)
	if err != nil {
		return WorkbookTemplatesClientCreateOrUpdateResponse{}, err
	}
	httpResp, err := client.internal.Pipeline().Do(req)
	if err != nil {
		return WorkbookTemplatesClientCreateOrUpdateResponse{}, err
	}
	if !runtime.HasStatusCode(httpResp, http.StatusOK, http.StatusCreated) {
		err = runtime.NewResponseError(httpResp)
		return WorkbookTemplatesClientCreateOrUpdateResponse{}, err
	}
	resp, err := client.createOrUpdateHandleResponse(httpResp)
	return resp, err
}

// createOrUpdateCreateRequest creates the CreateOrUpdate request.
func (client *WorkbookTemplatesClient) createOrUpdateCreateRequest(ctx context.Context, resourceGroupName string, resourceName string, workbookTemplateProperties WorkbookTemplate, _ *WorkbookTemplatesClientCreateOrUpdateOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Insights/workbooktemplates/{resourceName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if resourceName == "" {
		return nil, errors.New("parameter resourceName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceName}", url.PathEscape(resourceName))
	req, err := runtime.NewRequest(ctx, http.MethodPut, runtime.JoinPaths(client.internal.Endpoint(), urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2020-11-20")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header["Accept"] = []string{"application/json"}
	if err := runtime.MarshalAsJSON(req, workbookTemplateProperties); err != nil {
		return nil, err
	}
	return req, nil
}

// createOrUpdateHandleResponse handles the CreateOrUpdate response.
func (client *WorkbookTemplatesClient) createOrUpdateHandleResponse(resp *http.Response) (WorkbookTemplatesClientCreateOrUpdateResponse, error) {
	result := WorkbookTemplatesClientCreateOrUpdateResponse{}
	if err := runtime.UnmarshalAsJSON(resp, &result.WorkbookTemplate); err != nil {
		return WorkbookTemplatesClientCreateOrUpdateResponse{}, err
	}
	return result, nil
}

// Delete - Delete a workbook template.
// If the operation fails it returns an *azcore.ResponseError type.
//
// Generated from API version 2020-11-20
//   - resourceGroupName - The name of the resource group. The name is case insensitive.
//   - resourceName - The name of the Application Insights component resource.
//   - options - WorkbookTemplatesClientDeleteOptions contains the optional parameters for the WorkbookTemplatesClient.Delete
//     method.
func (client *WorkbookTemplatesClient) Delete(ctx context.Context, resourceGroupName string, resourceName string, options *WorkbookTemplatesClientDeleteOptions) (WorkbookTemplatesClientDeleteResponse, error) {
	var err error
	const operationName = "WorkbookTemplatesClient.Delete"
	ctx = context.WithValue(ctx, runtime.CtxAPINameKey{}, operationName)
	ctx, endSpan := runtime.StartSpan(ctx, operationName, client.internal.Tracer(), nil)
	defer func() { endSpan(err) }()
	req, err := client.deleteCreateRequest(ctx, resourceGroupName, resourceName, options)
	if err != nil {
		return WorkbookTemplatesClientDeleteResponse{}, err
	}
	httpResp, err := client.internal.Pipeline().Do(req)
	if err != nil {
		return WorkbookTemplatesClientDeleteResponse{}, err
	}
	if !runtime.HasStatusCode(httpResp, http.StatusOK, http.StatusNoContent) {
		err = runtime.NewResponseError(httpResp)
		return WorkbookTemplatesClientDeleteResponse{}, err
	}
	return WorkbookTemplatesClientDeleteResponse{}, nil
}

// deleteCreateRequest creates the Delete request.
func (client *WorkbookTemplatesClient) deleteCreateRequest(ctx context.Context, resourceGroupName string, resourceName string, _ *WorkbookTemplatesClientDeleteOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Insights/workbooktemplates/{resourceName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if resourceName == "" {
		return nil, errors.New("parameter resourceName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceName}", url.PathEscape(resourceName))
	req, err := runtime.NewRequest(ctx, http.MethodDelete, runtime.JoinPaths(client.internal.Endpoint(), urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2020-11-20")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header["Accept"] = []string{"application/json"}
	return req, nil
}

// Get - Get a single workbook template by its resourceName.
// If the operation fails it returns an *azcore.ResponseError type.
//
// Generated from API version 2020-11-20
//   - resourceGroupName - The name of the resource group. The name is case insensitive.
//   - resourceName - The name of the Application Insights component resource.
//   - options - WorkbookTemplatesClientGetOptions contains the optional parameters for the WorkbookTemplatesClient.Get method.
func (client *WorkbookTemplatesClient) Get(ctx context.Context, resourceGroupName string, resourceName string, options *WorkbookTemplatesClientGetOptions) (WorkbookTemplatesClientGetResponse, error) {
	var err error
	const operationName = "WorkbookTemplatesClient.Get"
	ctx = context.WithValue(ctx, runtime.CtxAPINameKey{}, operationName)
	ctx, endSpan := runtime.StartSpan(ctx, operationName, client.internal.Tracer(), nil)
	defer func() { endSpan(err) }()
	req, err := client.getCreateRequest(ctx, resourceGroupName, resourceName, options)
	if err != nil {
		return WorkbookTemplatesClientGetResponse{}, err
	}
	httpResp, err := client.internal.Pipeline().Do(req)
	if err != nil {
		return WorkbookTemplatesClientGetResponse{}, err
	}
	if !runtime.HasStatusCode(httpResp, http.StatusOK) {
		err = runtime.NewResponseError(httpResp)
		return WorkbookTemplatesClientGetResponse{}, err
	}
	resp, err := client.getHandleResponse(httpResp)
	return resp, err
}

// getCreateRequest creates the Get request.
func (client *WorkbookTemplatesClient) getCreateRequest(ctx context.Context, resourceGroupName string, resourceName string, _ *WorkbookTemplatesClientGetOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Insights/workbooktemplates/{resourceName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if resourceName == "" {
		return nil, errors.New("parameter resourceName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceName}", url.PathEscape(resourceName))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.internal.Endpoint(), urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2020-11-20")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header["Accept"] = []string{"application/json"}
	return req, nil
}

// getHandleResponse handles the Get response.
func (client *WorkbookTemplatesClient) getHandleResponse(resp *http.Response) (WorkbookTemplatesClientGetResponse, error) {
	result := WorkbookTemplatesClientGetResponse{}
	if err := runtime.UnmarshalAsJSON(resp, &result.WorkbookTemplate); err != nil {
		return WorkbookTemplatesClientGetResponse{}, err
	}
	return result, nil
}

// NewListByResourceGroupPager - Get all Workbook templates defined within a specified resource group.
//
// Generated from API version 2020-11-20
//   - resourceGroupName - The name of the resource group. The name is case insensitive.
//   - options - WorkbookTemplatesClientListByResourceGroupOptions contains the optional parameters for the WorkbookTemplatesClient.NewListByResourceGroupPager
//     method.
func (client *WorkbookTemplatesClient) NewListByResourceGroupPager(resourceGroupName string, options *WorkbookTemplatesClientListByResourceGroupOptions) *runtime.Pager[WorkbookTemplatesClientListByResourceGroupResponse] {
	return runtime.NewPager(runtime.PagingHandler[WorkbookTemplatesClientListByResourceGroupResponse]{
		More: func(page WorkbookTemplatesClientListByResourceGroupResponse) bool {
			return false
		},
		Fetcher: func(ctx context.Context, page *WorkbookTemplatesClientListByResourceGroupResponse) (WorkbookTemplatesClientListByResourceGroupResponse, error) {
			ctx = context.WithValue(ctx, runtime.CtxAPINameKey{}, "WorkbookTemplatesClient.NewListByResourceGroupPager")
			req, err := client.listByResourceGroupCreateRequest(ctx, resourceGroupName, options)
			if err != nil {
				return WorkbookTemplatesClientListByResourceGroupResponse{}, err
			}
			resp, err := client.internal.Pipeline().Do(req)
			if err != nil {
				return WorkbookTemplatesClientListByResourceGroupResponse{}, err
			}
			if !runtime.HasStatusCode(resp, http.StatusOK) {
				return WorkbookTemplatesClientListByResourceGroupResponse{}, runtime.NewResponseError(resp)
			}
			return client.listByResourceGroupHandleResponse(resp)
		},
		Tracer: client.internal.Tracer(),
	})
}

// listByResourceGroupCreateRequest creates the ListByResourceGroup request.
func (client *WorkbookTemplatesClient) listByResourceGroupCreateRequest(ctx context.Context, resourceGroupName string, _ *WorkbookTemplatesClientListByResourceGroupOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Insights/workbooktemplates"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.internal.Endpoint(), urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2020-11-20")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header["Accept"] = []string{"application/json"}
	return req, nil
}

// listByResourceGroupHandleResponse handles the ListByResourceGroup response.
func (client *WorkbookTemplatesClient) listByResourceGroupHandleResponse(resp *http.Response) (WorkbookTemplatesClientListByResourceGroupResponse, error) {
	result := WorkbookTemplatesClientListByResourceGroupResponse{}
	if err := runtime.UnmarshalAsJSON(resp, &result.WorkbookTemplatesListResult); err != nil {
		return WorkbookTemplatesClientListByResourceGroupResponse{}, err
	}
	return result, nil
}

// Update - Updates a workbook template that has already been added.
// If the operation fails it returns an *azcore.ResponseError type.
//
// Generated from API version 2020-11-20
//   - resourceGroupName - The name of the resource group. The name is case insensitive.
//   - resourceName - The name of the Application Insights component resource.
//   - options - WorkbookTemplatesClientUpdateOptions contains the optional parameters for the WorkbookTemplatesClient.Update
//     method.
func (client *WorkbookTemplatesClient) Update(ctx context.Context, resourceGroupName string, resourceName string, options *WorkbookTemplatesClientUpdateOptions) (WorkbookTemplatesClientUpdateResponse, error) {
	var err error
	const operationName = "WorkbookTemplatesClient.Update"
	ctx = context.WithValue(ctx, runtime.CtxAPINameKey{}, operationName)
	ctx, endSpan := runtime.StartSpan(ctx, operationName, client.internal.Tracer(), nil)
	defer func() { endSpan(err) }()
	req, err := client.updateCreateRequest(ctx, resourceGroupName, resourceName, options)
	if err != nil {
		return WorkbookTemplatesClientUpdateResponse{}, err
	}
	httpResp, err := client.internal.Pipeline().Do(req)
	if err != nil {
		return WorkbookTemplatesClientUpdateResponse{}, err
	}
	if !runtime.HasStatusCode(httpResp, http.StatusOK) {
		err = runtime.NewResponseError(httpResp)
		return WorkbookTemplatesClientUpdateResponse{}, err
	}
	resp, err := client.updateHandleResponse(httpResp)
	return resp, err
}

// updateCreateRequest creates the Update request.
func (client *WorkbookTemplatesClient) updateCreateRequest(ctx context.Context, resourceGroupName string, resourceName string, options *WorkbookTemplatesClientUpdateOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Insights/workbooktemplates/{resourceName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if resourceName == "" {
		return nil, errors.New("parameter resourceName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceName}", url.PathEscape(resourceName))
	req, err := runtime.NewRequest(ctx, http.MethodPatch, runtime.JoinPaths(client.internal.Endpoint(), urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2020-11-20")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header["Accept"] = []string{"application/json"}
	if options != nil && options.WorkbookTemplateUpdateParameters != nil {
		if err := runtime.MarshalAsJSON(req, *options.WorkbookTemplateUpdateParameters); err != nil {
			return nil, err
		}
		return req, nil
	}
	return req, nil
}

// updateHandleResponse handles the Update response.
func (client *WorkbookTemplatesClient) updateHandleResponse(resp *http.Response) (WorkbookTemplatesClientUpdateResponse, error) {
	result := WorkbookTemplatesClientUpdateResponse{}
	if err := runtime.UnmarshalAsJSON(resp, &result.WorkbookTemplate); err != nil {
		return WorkbookTemplatesClientUpdateResponse{}, err
	}
	return result, nil
}
