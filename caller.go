// Package govh provides a HTTP wrapper to OVH API.
// It allows to easily perform requests to API.
package govh

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"
)

var (
	ApiUrl = map[string]string{
		"ovh-eu":   "https://api.ovh.com/1.0",
		"ovh-ca":   "https://ca.api.ovh.com/1.0",
		"runabove": "https://api.runabove.com/1.0",
	}
)

// Caller is a struct representing a caller to OVH API.
type Caller struct {
	// Your application key, given when you registered your application inside OVH.
	ApplicationKey string
	// Your application secret.
	ApplicationSecret string
	// A consumer key represent a third-legs key, matching your application, an OVH user, and a scope.
	ConsumerKey string
	// OVH API Url.
	Url string

	delay int
}

// NewCaller create a new caller.
// It also call Time() to get difference between OVH API time and local time
func NewCaller(endpoint, applicationKey, applicationSecret, consumerKey string) (*Caller, error) {

	url := ApiUrl[endpoint]
	if url == "" {
		return nil, errors.New(fmt.Sprintf("Invalid endpoint %s", endpoint))
	}

	caller := &Caller{
		ApplicationKey:    applicationKey,
		ApplicationSecret: applicationSecret,
		ConsumerKey:       consumerKey,
		Url:               url,
	}

	currentTime := time.Now().Unix()
	ovhTime, err := caller.Time()
	if err != nil {
		return nil, err
	}

	caller.delay = ovhTime - int(currentTime)

	return caller, nil
}

// Ping perform a ping to OVH API.
// In fact, ping is just a /auth/time call, in order to check if API is up.
func (caller *Caller) Ping() error {
	_, err := caller.Time()
	return err
}

// Get time from OVH API, by asking GET /auth/time.
// Time is used to sign requests and to make all calls to API.
func (caller *Caller) Time() (int, error) {
	request, err := http.NewRequest("GET", fmt.Sprintf("%s/auth/time", caller.Url), nil)
	if err != nil {
		return 0, err
	}

	result, err := http.DefaultClient.Do(request)
	if err != nil {
		return 0, err
	}
	defer result.Body.Close()

	body, err := ioutil.ReadAll(result.Body)
	if err != nil {
		return 0, err
	}

	if result.StatusCode != 200 {
		return 0, errors.New(fmt.Sprintf("API seems down, HTTP response: %d", result.StatusCode))
	}

	apiTime, err := strconv.Atoi(fmt.Sprintf("%s", body))
	if err != nil {
		return 0, err
	}

	return apiTime, nil
}

// Response when asking a new consumerKey.
type GetCKResponse struct {
	// Consumer key, which need to be validated by customer.
	ConsumerKey string
	// Current status, should be always "pendingValidation".
	Status string
	// URL to redirect user in order to log in.
	ValidationUrl string
}

// Parameters to fill in order to ask a new consumerKey.
type GetCKParams struct {
	// Scope for the new consumerKey.
	AccessRules []*AccessRule `json:"accessRules"`
	// URL to redirect user after a successful login on GetCKResponse.ValidationUrl.
	// If set to empty string, user stays on OVH website, but the consumerKey is validated.
	Redirection string `json:"redirection"`
}

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

// GetConsumerKey ask OVH API for a new consumerKey
// Store the received consumerKey in Caller
// Consumer key will be defined by the given parameters
func (caller *Caller) GetConsumerKey(ckParams *GetCKParams) (*GetCKResponse, error) {

	params, err := json.Marshal(ckParams)
	if err != nil {
		return nil, NewError(err.Error(), http.StatusInternalServerError)
	}

	request, err := http.NewRequest("POST", fmt.Sprintf("%s/auth/credential", caller.Url), bytes.NewReader(params))
	if err != nil {
		return nil, NewError(err.Error(), http.StatusInternalServerError)
	}
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("X-OVH-Application", caller.ApplicationKey)

	result, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, NewError(err.Error(), http.StatusInternalServerError)
	}
	defer result.Body.Close()

	body, err := ioutil.ReadAll(result.Body)
	if err != nil {
		return nil, NewError(err.Error(), http.StatusInternalServerError)
	}

	if result.StatusCode == 200 {
		askCK := new(GetCKResponse)
		err := json.Unmarshal(body, askCK)
		if err != nil {
			return nil, NewError(err.Error(), http.StatusInternalServerError)
		}

		caller.ConsumerKey = askCK.ConsumerKey

		return askCK, nil
	}

	apiError := new(ApiOvhError)
	err = json.Unmarshal(body, apiError)
	if err != nil {
		return nil, NewError(err.Error(), http.StatusInternalServerError)
	}

	apiError.Code = result.StatusCode
	return nil, apiError
}

// CallApi makes a new call to the OVH API
// ApplicationKey, ApplicationSecret and ConsumerKey must be set on Caller
// Returns the unmarshal json object or error if any occured
func (caller *Caller) CallApi(url, method string, body interface{}, typeResult interface{}) error {
	var params []byte
	if body != nil {
		var err error
		params, err = json.Marshal(body)
		if err != nil {
			return NewError(err.Error(), http.StatusInternalServerError)
		}
	}

	completeUrl := fmt.Sprintf("%s%s", caller.Url, url)
	request, err := http.NewRequest(method, completeUrl, bytes.NewReader(params))
	if err != nil {
		return NewError(err.Error(), http.StatusInternalServerError)
	}

	timestamp := int(time.Now().Unix()) + caller.delay

	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("X-Ovh-Timestamp", fmt.Sprintf("%d", timestamp))
	request.Header.Add("X-Ovh-Application", caller.ApplicationKey)
	request.Header.Add("X-Ovh-Consumer", caller.ConsumerKey)
	signature := caller.getSignature(method, completeUrl, fmt.Sprintf("%s", params), timestamp)
	request.Header.Add("X-Ovh-Signature", signature)

	result, err := http.DefaultClient.Do(request)
	if err != nil {
		return NewError(err.Error(), http.StatusInternalServerError)
	}
	defer result.Body.Close()

	resBody, err := ioutil.ReadAll(result.Body)
	if err != nil {
		return NewError(err.Error(), http.StatusInternalServerError)
	}

	if result.StatusCode >= 200 && result.StatusCode < 300 {
		if len(resBody) > 0 && typeResult != nil {
			err := json.Unmarshal(resBody, &typeResult)
			if err != nil {
				return NewError(err.Error(), http.StatusInternalServerError)
			}
		}

		return nil
	}

	apiError := new(ApiOvhError)
	err = json.Unmarshal(resBody, apiError)
	if err != nil {
		return NewError(err.Error(), http.StatusInternalServerError)
	}

	apiError.Code = result.StatusCode
	return apiError
}

func (caller *Caller) getSignature(method, url, body string, apiTime int) string {
	h := sha1.New()
	sig := fmt.Sprintf("%s+%s+%s+%s+%s+%d", caller.ApplicationSecret, caller.ConsumerKey, method, url, body, apiTime)
	io.WriteString(h, sig)
	return "$1$" + hex.EncodeToString(h.Sum(nil))
}
