// Package govh provides a HTTP wrapper to OVH API.
// It allows to easily perform requests to API.
package govh

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// API URLs
var APIURL = map[string]string{
	"ovh-eu":   "https://api.ovh.com/1.0",
	"ovh-ca":   "https://ca.api.ovh.com/1.0",
	"runabove": "https://api.runabove.com/1.0",
}

// Caller is a struct representing a caller to OVH API.
type Caller struct {
	// Your application key, given when you registered your application inside OVH.
	ApplicationKey string
	// Your application secret.
	ApplicationSecret string
	// A consumer key represent a third-legs key, matching your application, an OVH user, and a scope.
	ConsumerKey string
	// OVH API Url.
	URL string
	// Time lag between the caller's clock and the OVH API
	delay time.Duration
}

// NewCaller creates a new caller.
// It also call Time() to get difference between OVH API time and local time
func NewCaller(endpoint, applicationKey, applicationSecret, consumerKey string) (*Caller, error) {
	url, ok := APIURL[endpoint]
	if !ok {
		return nil, fmt.Errorf("Invalid endpoint %q", endpoint)
	}

	caller := &Caller{
		ApplicationKey:    applicationKey,
		ApplicationSecret: applicationSecret,
		ConsumerKey:       consumerKey,
		URL:               url,
	}

	ovhTime, err := caller.Time()
	if err != nil {
		return nil, err
	}

	caller.delay = time.Since(*ovhTime)

	return caller, nil
}

// Ping performs a ping to OVH API.
// In fact, ping is just a /auth/time call, in order to check if API is up.
func (caller *Caller) Ping() error {
	_, err := caller.Time()
	return err
}

// Time returns time from the OVH API, by asking GET /auth/time.
// Time is used to sign requests and to make all calls to API.
func (caller *Caller) Time() (*time.Time, error) {
	request, err := http.NewRequest("GET", fmt.Sprintf("%s/auth/time", caller.URL), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Add("Content-Type", "application/json")

	result, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer result.Body.Close()

	body, err := ioutil.ReadAll(result.Body)
	if err != nil {
		return nil, err
	}

	if result.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API seems down, HTTP response: %d", result.StatusCode)
	}

	ts, err := strconv.Atoi(string(body))
	if err != nil {
		return nil, err
	}

	t := time.Unix(int64(ts), 0)

	return &t, nil
}

// GetCKResponse represents the response when asking a new consumerKey.
type GetCKResponse struct {
	// Consumer key, which need to be validated by customer.
	ConsumerKey string `json:"consumerKey"`
	// Current status, should be always "pendingValidation".
	Status string `json:"state"`
	// URL to redirect user in order to log in.
	ValidationURL string `json:"validationUrl"`
}

// GetCKParams represents the parameters to fill in order to ask a new
// consumerKey.
type GetCKParams struct {
	// Scope for the new consumerKey.
	AccessRules []*AccessRule `json:"accessRules"`
	// URL to redirect user after a successful login on GetCKResponse.ValidationUrl.
	// If set to empty string, user stays on OVH website, but the consumerKey is validated.
	Redirection string `json:"redirection"`
}

// AccessRule represents a method allowed for a path
type AccessRule struct {
	// Allowed HTTP Method for the requested AccessRule.
	// Can be set to GET/POST/PUT/DELETE.
	Method string `json:"method"`
	// Allowed path.
	// Can be an exact string or a string with '*' char.
	// Example :
	// 		/me : only /me is authorized
	//		/* : all calls are authorized
	Path string `json:"path"`
}

// GetConsumerKey asks OVH API for a new consumerKey
// Store the received consumerKey in Caller
// Consumer key will be defined by the given parameters
func (caller *Caller) GetConsumerKey(ckParams *GetCKParams) (*GetCKResponse, error) {
	params, err := json.Marshal(ckParams)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequest("POST", fmt.Sprintf("%s/auth/credential", caller.URL), bytes.NewReader(params))
	if err != nil {
		return nil, err
	}
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("X-OVH-Application", caller.ApplicationKey)

	result, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer result.Body.Close()

	body, err := ioutil.ReadAll(result.Body)
	if err != nil {
		return nil, err
	}

	if result.StatusCode == 200 {
		askCK := new(GetCKResponse)
		err := json.Unmarshal(body, askCK)
		if err != nil {
			return nil, err
		}

		caller.ConsumerKey = askCK.ConsumerKey

		return askCK, nil
	}

	apiError := &ApiOvhError{Code: result.StatusCode}
	if err = json.Unmarshal(body, apiError); err != nil {
		return nil, err
	}

	return nil, apiError
}

// CallAPI makes a new call to the OVH API
// ApplicationKey, ApplicationSecret and ConsumerKey must be set on Caller
// Returns the unmarshal json object or error if any occured
func (caller *Caller) CallAPI(url, method string, body interface{}, typeResult interface{}) error {
	var params []byte
	if body != nil {
		var err error
		params, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}

	completeURL := caller.URL + url
	request, err := http.NewRequest(method, completeURL, bytes.NewReader(params))
	if err != nil {
		return err
	}

	timestamp := time.Now().Add(caller.delay).Unix()

	sig := caller.getSignature(method, completeURL, string(params), timestamp)
	for h, v := range map[string]string{
		"Content-Type":      "application/json",
		"X-Ovh-Timestamp":   strconv.FormatInt(timestamp, 10),
		"X-Ovh-Application": caller.ApplicationKey,
		"X-Ovh-Consumer":    caller.ConsumerKey,
		"X-Ovh-Signature":   sig,
	} {
		request.Header.Add(h, v)
	}

	result, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer result.Body.Close()

	resBody, err := ioutil.ReadAll(result.Body)
	if err != nil {
		return err
	}

	// >= 200 && < 300
	if result.StatusCode >= http.StatusOK && result.StatusCode < http.StatusMultipleChoices {
		if len(resBody) > 0 && typeResult != nil {
			if err := json.Unmarshal(resBody, &typeResult); err != nil {
				return err
			}
		}

		return nil
	}

	apiError := &ApiOvhError{Code: result.StatusCode}
	if err = json.Unmarshal(resBody, apiError); err != nil {
		return err
	}

	return apiError
}

func (caller *Caller) getSignature(method, url, body string, timestamp int64) string {
	h := sha1.New()
	sig := strings.Join([]string{
		caller.ApplicationSecret,
		caller.ConsumerKey,
		method,
		url,
		body,
		strconv.FormatInt(timestamp, 10),
	}, "+")
	io.WriteString(h, sig)
	return "$1$" + hex.EncodeToString(h.Sum(nil))
}
