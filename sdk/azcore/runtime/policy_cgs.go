package runtime

import (
	"fmt"
	"strings"
	"encoding/json"
	"os"
	"sync"
    "net/http"
	"net/url"

    "github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

const (
    CgsProxyHostHeader = "CGS-Proxy-Host"
    CgsProxyDestinationHeader = "CGS-Proxy-Destination"
)

var (
	cgsNoPe bool 
	cgsProxyHost string
	cgsProxyProtocolScheme string
	cgsProxyHeaders map[string]string
	cgs_once         sync.Once
)

type CgsPolicy struct{}

func NewCgsPolicy() *CgsPolicy {
	// load the proxy environment variables

	cgs_once.Do(func() { // Ensure this runs only once
		cgsProxyHeaders = make(map[string]string)
		envValue := os.Getenv("CGS_PROXY_HEADERS")
		if envValue == "" {
			fmt.Printf("CGSOnce: Headers are empty: \n")
			return
		}

		// Decode the JSON string into the map
		if err := json.Unmarshal([]byte(envValue), &cgsProxyHeaders); err != nil {
			fmt.Printf("CGSOnce: Unmarshal of headers json failed : %s\n", envValue)
			cgsProxyHeaders = nil
			return
		}

		endpoint := os.Getenv("CGS_PROXY_ENDPOINT")
		fmt.Printf("CGSOnce: ENDPOINT: %s\n", endpoint)
		if endpoint == "" {
			fmt.Printf("CGSOnce: endpoint is empty\n")
			return
		}
		parsedURL, err := url.Parse(endpoint)
		if err != nil {
			fmt.Printf("CGSOnce: URL Parsing failed: %s\n", endpoint)
			return
		}
		cgsProxyHost = parsedURL.Host
		cgsProxyProtocolScheme = parsedURL.Scheme
		fmt.Printf("CGSOnce: endpoint-host: %s, protocl: %s\n", cgsProxyHost, cgsProxyProtocolScheme)

		no_pe := os.Getenv("CGS_PROXY_NO_PE")
		fmt.Printf("CGSOnce: NO_PE: %s\n", no_pe)
		if no_pe == "" {
			cgsNoPe = true
		} else {
			if strings.EqualFold(no_pe, "yes") ||  strings.EqualFold(no_pe, "true") || strings.EqualFold(no_pe, "1") {
				cgsNoPe = true
			} else {
				cgsNoPe = false 
			}
		}
		fmt.Printf("CGSOnce: CgsNoPe: %t\n", cgsNoPe)
	})
    return &CgsPolicy{}
}

func (c *CgsPolicy) Do(req *policy.Request) (*http.Response, error) {
    rawReq := req.Raw() // Get underlying *http.Request

	// if no proxy is set, we are done with this stage of the pipeline
	if cgsProxyHost == "" {
    	return req.Next()
	}

	// any URL other than blob or files, we don't intend to send to cgs
	if ! strings.Contains(rawReq.Host, "blob.core.windows.net") &&
		! strings.Contains(rawReq.Host, "file.core.windows.net") {
    	return req.Next()
	}

	// as part of the pipline's stage add headers
	for key, value := range cgsProxyHeaders {
		if (key != CgsProxyHostHeader) {
			rawReq.Header.Set(key, value)
		}
	}

	// set the host
	proxy_host := rawReq.Host
	rawReq.Header.Set(CgsProxyHostHeader, proxy_host)

	// if there is no Pe, we need to determine the destination dynamically, else its from env,
	// the destination specified by the environment variable
	if (cgsNoPe) {
		proxy_destination := rawReq.URL.Scheme + "://" + rawReq.URL.Host
		rawReq.Header.Set(CgsProxyDestinationHeader, proxy_destination)
	}

	// set the request host and URL parameters
	rawReq.Host = cgsProxyHost
	rawReq.URL.Scheme = cgsProxyProtocolScheme
	rawReq.URL.Host = cgsProxyHost
	// fmt.Printf("Host = %s, URL Host = %s, Scheme = %s\n", rawReq.Host, rawReq.URL.Host, rawReq.URL.Scheme)

    // Continue with the next policy
    return req.Next()
}

