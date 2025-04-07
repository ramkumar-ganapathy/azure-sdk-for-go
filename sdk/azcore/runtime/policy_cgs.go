package runtime

import (
	"fmt"
	"strings"
	"encoding/json"
	"encoding/binary"
	"os"
	"sync"
	"sync/atomic"
    "net/http"
	"net/url"
	"github.com/google/uuid"
	"time"
	"context"
	"errors"
	// "math/rand"

    "github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

const (
    CgsProxyHostHeader = "CGS-Proxy-Host"
    CgsProxyDestinationHeader = "CGS-Proxy-Destination"
	CgsProxyClientRequestId = "CGS-Proxy-Client-Request-ID"
	CgsProxyAuthorization = "CGS-Proxy-Authorization"
)

var (
	cgsNoPe bool 
	cgsProxyHost string
	cgsProxyProtocolScheme string
	cgsProxyHeaders map[string]string
	cgs_once         sync.Once
	base_uuid		 uuid.UUID
	base_bytes	     [16]byte
	request_id		 uint64
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

		base_uuid = uuid.New()
		base_bytes = base_uuid
		for i := 8; i < 16; i++ {
			base_bytes[i] = 0x00
		}

		cgs_stats_init()
		fmt.Printf("CGSOnce: stats initialized")

		// rand.Seed(time.Now().UnixNano())
	})
    return &CgsPolicy{}
}

func getNewRequestId() string {
	var u [16]byte
	copy(u[:8], base_bytes[:8])

	seq := atomic.AddUint64(&request_id, 1)

	binary.BigEndian.PutUint64(u[8:], uint64(seq))

	id := uuid.Must(uuid.FromBytes(u[:]))
	return id.String()
}

func getUntilDuration(ctx context.Context) time.Duration {
	deadline, ok := ctx.Deadline()
	if ok {
		return time.Until(deadline)
	} else {
		return 0
	}
}

func (c *CgsPolicy) Do(req_in *policy.Request) (*http.Response, error) {
	use_cgs := true 

    rawReq := req_in.Raw() // Get underlying *http.Request

	// if no proxy is set, we are done with this stage of the pipeline
	if cgsProxyHost == "" {
		use_cgs = false
		// return req_in.Next()
	}

	// any URL other than blob or files, we don't intend to send to cgs
	if ! strings.Contains(rawReq.Host, "blob.core.windows.net") &&
		! strings.Contains(rawReq.Host, "file.core.windows.net") {
		use_cgs = false
		// return req_in.Next()
	}

	origURL := rawReq.URL

    // if cgs is in use, add headers
	if (use_cgs) {
		// as part of the pipline's stage add headers
		for key, value := range cgsProxyHeaders {
			if (key != CgsProxyHostHeader) {
				rawReq.Header.Set(key, value)
			}
		}

		auth_token, err := CgsGetAuthToken()
		if err == nil {
			rawReq.Header.Set(CgsProxyAuthorization, "Bearer "+auth_token)
		}

		rawReq.Header.Set(CgsProxyClientRequestId, getNewRequestId())

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

		/*
    	dump_request_details := func(req *http.Request) {
			fmt.Println("CGSPolicy: OriginalURL = ", origURL)
			fmt.Println("CGSPolicy: Request Details:")
			fmt.Println("CGSPolicy: Request URI:", origURL)
			fmt.Println("CGSPolicy: Request Response Headers:")
			for name, values := range req.Header {
				fmt.Println("CGSPolicy Request Header: ", name, "=", values)
			}
		}
		*/
	}

	start := time.Now()
    resp, err := req_in.Next()
 	end := time.Now()
	lat := end.Sub(start).Milliseconds()
	if err != nil {
		fmt.Println("CGS Policy: Req failed :", err)
		if ! errors.Is(err, context.Canceled) {
			fmt.Println("CGS Policy: not-cancelled, other error")
		}
		cgs_stats_report(lat, false)
		fmt.Println("CGS Policy: Req failed : latency = ", lat)
		return nil, err
	}

    dump_response_headers := func(resp *http.Response) {
        fmt.Println("CGSPolicy: Details:")
        fmt.Println("CGSPolicy: URI:", origURL)
        fmt.Println("CGSPolicy: Response Headers:")
        for name, values := range resp.Header {
            fmt.Println("CGSPolicy Header: ", name, "=", values)
        }
    }

    if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		cgs_stats_report(lat, true)
    } else if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		cgs_stats_report(lat, false)
        fmt.Printf("CGSPolicy: Client Error! Response Status: %s\n", resp.Status)
		dump_response_headers(resp)
    } else if resp.StatusCode >= 500 && resp.StatusCode < 600 {
		cgs_stats_report(lat, false)
        fmt.Printf("CGSPolicy: Server Error! Response Status: %s\n", resp.Status)
		dump_response_headers(resp)
    } else {
		cgs_stats_report(lat, false)
        fmt.Println("CGSPolicy: Response Status: Code: ", resp.StatusCode, "Status: ", resp.Status)
		dump_response_headers(resp)
    }

	return resp, nil
}

