// Package sigsci provides methods for interacting with the Signal Sciences API.
package sigsci

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const apiURL = "https://dashboard.signalsciences.net/api"

// Client is the API client
type Client struct {
	token string
}

// NewClient authenticates and returns a Client API client
func NewClient(email, password string) (Client, error) {
	sc := Client{}
	err := sc.authenticate(email, password)
	if err != nil {
		return Client{}, err
	}

	return sc, nil
}

// authenticate takes email/password and authenticates, attaching the
// returned token to the API client.
func (sc *Client) authenticate(email, password string) error {
	resp, err := http.PostForm(apiURL+"/v0/auth", url.Values{"email": {email}, "password": {password}})
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	var tr struct {
		Token string
	}

	err = json.NewDecoder(resp.Body).Decode(&tr)
	if err != nil {
		return err
	}

	sc.token = tr.Token

	return nil
}

func (sc *Client) doRequest(method, url, reqBody string) ([]byte, error) {
	client := &http.Client{}

	var b io.Reader
	if reqBody != "" {
		b = strings.NewReader(reqBody)
	}

	req, err := http.NewRequest(method, apiURL+url, b)
	if err != nil {
		return []byte{}, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", sc.token))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Set("User-Agent", "go-sigsci")

	resp, err := client.Do(req)
	if err != nil {
		return []byte{}, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte{}, err
	}

	switch method {
	case "GET":
		if resp.StatusCode != http.StatusOK {
			return body, errMsg(body)
		}
	case "POST":
		switch resp.StatusCode {
		case http.StatusOK, http.StatusCreated, http.StatusNoContent:
		default:
			return body, errMsg(body)
		}
	case "DELETE":
		if resp.StatusCode != http.StatusNoContent {
			return body, errMsg(body)
		}
	case "PATCH":
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
			return body, errMsg(body)
		}
	}

	return body, nil
}

func errMsg(b []byte) error {
	var errResp struct {
		Message string
	}

	err := json.Unmarshal(b, &errResp)
	if err != nil {
		return err
	}

	return errors.New(errResp.Message)
}

// Corp contains details for a corp.
type Corp struct {
	Name                   string
	DisplayName            string
	SmallIconURI           string
	Created                time.Time
	SiteLimit              int
	Sites                  map[string]string
	AuthType               string
	MFAEnforced            bool
	SessionMaxAgeDashboard int
}

// corpsResponse is the response for list corps
type corpsResponse struct {
	Data []Corp
}

// ListCorps lists corps.
func (sc *Client) ListCorps() ([]Corp, error) {
	resp, err := sc.doRequest("GET", "/v0/corps", "")
	if err != nil {
		return []Corp{}, err
	}

	var cr corpsResponse
	err = json.Unmarshal(resp, &cr)
	if err != nil {
		return []Corp{}, err
	}

	return cr.Data, nil
}

// GetCorp gets a corp by name.
func (sc *Client) GetCorp(corpName string) (Corp, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s", corpName), "")
	if err != nil {
		return Corp{}, err
	}

	var corp Corp
	err = json.Unmarshal(resp, &corp)
	if err != nil {
		return Corp{}, err
	}

	return corp, nil
}

// UpdateCorpBody is the body for the UpdateCorp method.
type UpdateCorpBody struct {
	DisplayName            string `json:"displayName,omitempty"`
	SmallIconURI           string `json:"smallIconURI,omitempty"`
	SessionMaxAgeDashboard int    `json:"sessionMaxAgeDashboard,omitempty"`
}

// UpdateCorp updates a corp by name.
func (sc *Client) UpdateCorp(corpName string, body UpdateCorpBody) (Corp, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return Corp{}, err
	}

	resp, err := sc.doRequest("PATCH", fmt.Sprintf("/v0/corps/%s", corpName), string(b))
	if err != nil {
		return Corp{}, err
	}

	var corp Corp
	err = json.Unmarshal(resp, &corp)
	if err != nil {
		return Corp{}, err
	}

	return corp, nil
}

// Role is a corp or site role
type Role string

// All available Roles
const (
	RoleSiteNoAccess = Role("none")
	RoleSiteUnknown  = Role("unknown")
	RoleSiteOwner    = Role("owner")
	RoleSiteAdmin    = Role("admin")
	RoleSiteUser     = Role("user")
	RoleSiteObserver = Role("observer")
	RoleCorpOwner    = Role("corpOwner")
	RoleCorpUser     = Role("corpUser")
)

// CorpUser contains details for a corp user.
type CorpUser struct {
	Name        string
	Email       string
	Memberships map[string]string
	Role        string
	Status      string
	MFAEnabled  bool
	AuthStatus  string
	Created     time.Time
}

// corpUsersResponse is the response for list corp users
type corpUsersResponse struct {
	Data []CorpUser
}

// ListCorpUsers lists corp users.
func (sc *Client) ListCorpUsers(corpName string) ([]CorpUser, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/users", corpName), "")
	if err != nil {
		return []CorpUser{}, err
	}

	var cur corpUsersResponse
	err = json.Unmarshal(resp, &cur)
	if err != nil {
		return []CorpUser{}, err
	}

	return cur.Data, nil
}

// GetCorpUser gets a corp user by email.
func (sc *Client) GetCorpUser(corpName, email string) (CorpUser, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/users/%s", corpName, email), "")
	if err != nil {
		return CorpUser{}, err
	}

	var cu CorpUser
	err = json.Unmarshal(resp, &cu)
	if err != nil {
		return CorpUser{}, err
	}

	return cu, nil
}

// DeleteCorpUser deletes a user from the given corp.
func (sc *Client) DeleteCorpUser(corpName, email string) error {
	_, err := sc.doRequest("DELETE", fmt.Sprintf("/v0/corps/%s/users/%s", corpName, email), "")

	return err
}

type inviteMemberships struct {
	Data []SiteMembership `json:"data"`
}

// CorpUserInvite is the request struct for inviting a user to a corp.
type CorpUserInvite struct {
	Role        Role              `json:"role"`
	Memberships inviteMemberships `json:"memberships"`
}

// NewCorpUserInvite creates a new invitation struct for inviting a user to a corp.
func NewCorpUserInvite(corpRole Role, memberships []SiteMembership) CorpUserInvite {
	return CorpUserInvite{
		Role: corpRole,
		Memberships: inviteMemberships{
			Data: memberships,
		},
	}
}

// InviteUser invites a user by email to a corp.
func (sc *Client) InviteUser(corpName, email string, invite CorpUserInvite) (CorpUser, error) {
	body, err := json.Marshal(invite)
	if err != nil {
		return CorpUser{}, err
	}

	resp, err := sc.doRequest("POST", fmt.Sprintf("/v0/corps/%s/users/%s/invite", corpName, email), string(body))
	if err != nil {
		return CorpUser{}, err
	}

	var cu CorpUser
	err = json.Unmarshal(resp, &cu)
	if err != nil {
		return CorpUser{}, err
	}

	return cu, nil
}

type topAttackType struct {
	TagName    string
	TagCount   int
	TotalCount int
}

type topAttackSource struct {
	CountryCode  string
	CountryName  string
	RequestCount int
	TotalCount   int
}

// OverviewSite is a site in the overview report.
type OverviewSite struct {
	Name             string
	DisplayName      string
	TotalCount       int
	BlockedCount     int
	FlaggedCount     int
	AttackCount      int
	FlaggedIPCount   int
	TopAttackTypes   []topAttackType
	TopAttackSources []topAttackSource
}

// overviewResponse contains the overview report data.
type overviewResponse struct {
	Data []OverviewSite
}

// GetOverviewReport gets the overview report data for a given corp.
func (sc *Client) GetOverviewReport(corpName string, query url.Values) ([]OverviewSite, error) {
	url := fmt.Sprintf("/v0/corps/%s/reports/attacks", corpName)
	if query.Encode() != "" {
		url += "?" + query.Encode()
	}
	resp, err := sc.doRequest("GET", url, "")
	if err != nil {
		return []OverviewSite{}, err
	}

	var or overviewResponse
	err = json.Unmarshal(resp, &or)
	if err != nil {
		return []OverviewSite{}, err
	}

	return or.Data, nil
}

// ActivityEvent contains the data for activity page responses.
type ActivityEvent struct {
	ID          string
	EventType   string
	MsgData     map[string]string
	Message     string
	Attachments []struct{}
	Created     time.Time
}

// activityResponse is the response for the activity events endpoints.
type activityResponse struct {
	TotalCount int
	Next       map[string]string
	Data       []ActivityEvent
}

// ListCorpActivity lists activity events for a given corp.
func (sc *Client) ListCorpActivity(corpName string, limit, page int) ([]ActivityEvent, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/activity?limit=%d&page=%d", corpName, limit, page), "")
	if err != nil {
		return []ActivityEvent{}, err
	}

	var ar activityResponse
	err = json.Unmarshal(resp, &ar)
	if err != nil {
		return []ActivityEvent{}, err
	}

	return ar.Data, nil
}

// Site contains details for a site.
type Site struct {
	Name                 string
	DisplayName          string
	AgentLevel           string
	BlockHTTPCode        int
	BlockDurationSeconds int
	Created              time.Time
	Whitelist            map[string]string
	Blacklist            map[string]string
	Events               map[string]string
	Requests             map[string]string
	Redactions           map[string]string
	SuspiciousIPs        map[string]string
	Monitors             map[string]string
	Pathwhitelist        map[string]string
	Paramwhitelist       map[string]string
	Integrations         map[string]string
	HeaderLinks          map[string]string
	Agents               map[string]string
	Alerts               map[string]string
	AnalyticsEvents      map[string]string
	TopAttacks           map[string]string
	Members              map[string]string
}

// sitesResponse is the response for list sites.
type sitesResponse struct {
	Data []Site
}

// ListSites lists sites for a given corp.
func (sc *Client) ListSites(corpName string) ([]Site, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites", corpName), "")
	if err != nil {
		return []Site{}, err
	}

	var sr sitesResponse
	err = json.Unmarshal(resp, &sr)
	if err != nil {
		return []Site{}, err
	}

	return sr.Data, nil
}

// GetSite gets a site by name.
func (sc *Client) GetSite(corpName, siteName string) (Site, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites/%s", corpName, siteName), "")
	if err != nil {
		return Site{}, err
	}

	var site Site
	err = json.Unmarshal(resp, &site)
	if err != nil {
		return Site{}, err
	}

	return site, nil
}

// UpdateSiteBody is the body for the update site method.
type UpdateSiteBody struct {
	DisplayName          string `json:"displayName,omitempty"`
	AgentLevel           string `json:"agentLevel,omitempty"`
	BlockDurationSeconds int    `json:"blockDurationSeconds,omitempty"`
}

// UpdateSite updates a site by name.
func (sc *Client) UpdateSite(corpName, siteName string, body UpdateSiteBody) (Site, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return Site{}, err
	}

	resp, err := sc.doRequest("PATCH", fmt.Sprintf("/v0/corps/%s/sites/%s", corpName, siteName), string(b))
	if err != nil {
		return Site{}, err
	}

	var site Site
	err = json.Unmarshal(resp, &site)
	if err != nil {
		return Site{}, err
	}

	return site, nil
}

// CustomAlert contains the data for a custom alert
type CustomAlert struct {
	ID        string
	SiteID    string
	TagName   string
	Interval  int
	Threshold int
	Enabled   bool
	Action    string
	Created   time.Time
}

// customAlertsResponse is the response for the alerts endpoint
type customAlertsResponse struct {
	Data []CustomAlert
}

// ListCustomAlerts lists custom alerts for a given corp and site.
func (sc *Client) ListCustomAlerts(corpName, siteName string) ([]CustomAlert, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites/%s/alerts", corpName, siteName), "")
	if err != nil {
		return []CustomAlert{}, err
	}

	var car customAlertsResponse
	err = json.Unmarshal(resp, &car)
	if err != nil {
		return []CustomAlert{}, err
	}

	return car.Data, nil
}

// CustomAlertBody is the body for creating a custom alert.
type CustomAlertBody struct {
	TagName   string `json:"tagName"`
	LongName  string `json:"longName"`
	Interval  int    `json:"interval"`
	Threshold int    `json:"threshold"`
	Enabled   bool   `json:"enabled"`
	Action    string `json:"action"`
}

// CreateCustomAlert creates a custom alert.
func (sc *Client) CreateCustomAlert(corpName, siteName string, body CustomAlertBody) (CustomAlert, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return CustomAlert{}, err
	}

	resp, err := sc.doRequest("PATCH", fmt.Sprintf("/v0/corps/%s/sites/%s/alerts", corpName, siteName), string(b))
	if err != nil {
		return CustomAlert{}, err
	}

	var c CustomAlert
	err = json.Unmarshal(resp, &c)
	if err != nil {
		return CustomAlert{}, err
	}

	return c, nil
}

// GetCustomAlert gets a custom alert by ID
func (sc *Client) GetCustomAlert(corpName, siteName, id string) (CustomAlert, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites/%s/alerts/%s", corpName, siteName, id), "")
	if err != nil {
		return CustomAlert{}, err
	}

	var ca CustomAlert
	err = json.Unmarshal(resp, &ca)
	if err != nil {
		return CustomAlert{}, err
	}

	return ca, nil
}

// UpdateCustomAlert updates a custom alert by id.
func (sc *Client) UpdateCustomAlert(corpName, siteName, id string, body CustomAlertBody) (CustomAlert, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return CustomAlert{}, err
	}

	resp, err := sc.doRequest("PATCH", fmt.Sprintf("/v0/corps/%s/sites/%s/alerts/%s", corpName, siteName, id), string(b))
	if err != nil {
		return CustomAlert{}, err
	}

	var c CustomAlert
	err = json.Unmarshal(resp, &c)
	if err != nil {
		return CustomAlert{}, err
	}

	return c, err
}

// DeleteCustomAlert deletes a custom alert.
func (sc *Client) DeleteCustomAlert(corpName, siteName, id string) error {
	_, err := sc.doRequest("DELETE", fmt.Sprintf("/v0/corps/%s/sites/%s/alerts/%s", corpName, siteName, id), "")

	return err
}

// Event is a request event.
type Event struct {
	ID                string
	Timestamp         time.Time
	Source            string
	RemoteCountryCode string
	RemoteHostname    string
	UserAgents        []string
	Action            string
	Type              string
	Reasons           map[string]int
	RequestCount      int
	TagCount          int
	Window            int
	Expires           time.Time
	ExpiredBy         string
}

type eventsResponse struct {
	TotalCount int
	Next       map[string]string
	Data       []Event
}

// ListEvents lists events for a given site.
func (sc *Client) ListEvents(corpName, siteName string, query url.Values) ([]Event, error) {
	url := fmt.Sprintf("/v0/corps/%s/sites/%s/events", corpName, siteName)
	if query.Encode() != "" {
		url += "?" + query.Encode()
	}
	resp, err := sc.doRequest("GET", url, "")
	if err != nil {
		return []Event{}, err
	}

	var er eventsResponse
	err = json.Unmarshal(resp, &er)
	if err != nil {
		return []Event{}, err
	}

	return er.Data, nil
}

// GetEvent gets an event by ID.
func (sc *Client) GetEvent(corpName, siteName, id string) (Event, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites/%s/events/%s", corpName, siteName, id), "")
	if err != nil {
		return Event{}, err
	}

	var e Event
	err = json.Unmarshal(resp, &e)
	if err != nil {
		return Event{}, err
	}

	return e, nil
}

// ExpireEvent expires an event by ID.
func (sc *Client) ExpireEvent(corpName, siteName, id string) (Event, error) {
	resp, err := sc.doRequest("POST", fmt.Sprintf("/v0/corps/%s/sites/%s/events/%s/expire", corpName, siteName, id), "")
	if err != nil {
		return Event{}, err
	}

	var e Event
	err = json.Unmarshal(resp, &e)
	if err != nil {
		return Event{}, err
	}

	return e, nil
}

// RequestTag is a tag in a request
type RequestTag struct {
	Type     string
	Location string
	Value    string
	Detector string
}

// Request contains the data for a request
type Request struct {
	ID                string
	ServerHostname    string
	RemoteIP          string
	RemoteHostname    string
	RemoteCountryCode string
	UserAgent         string
	Timestamp         time.Time
	Method            string
	ServerName        string
	Protocol          string
	Path              string
	URI               string
	ResponseCode      int
	ResponseSize      int
	ResponseMillis    int
	AgentResponseCode int
	Tags              []RequestTag
}

// requestsResponse is the response for the search requests endpoint
type requestsResponse struct {
	TotalCount int
	Next       map[string]string
	Data       []Request
}

// SearchRequests searches requests.
func (sc *Client) SearchRequests(corpName, siteName string, query url.Values) (next string, requests []Request, err error) {
	url := fmt.Sprintf("/v0/corps/%s/sites/%s/requests", corpName, siteName)
	if query.Encode() != "" {
		url += "?" + query.Encode()
	}
	resp, err := sc.doRequest("GET", url, "")
	if err != nil {
		return "", []Request{}, err
	}

	var r requestsResponse
	err = json.Unmarshal(resp, &r)
	if err != nil {
		return "", []Request{}, err
	}

	return r.Next["uri"], r.Data, nil
}

// GetRequest gets a request by id.
func (sc *Client) GetRequest(corpName, siteName, id string) (Request, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites/%s/requests/%s", corpName, siteName, id), "")
	if err != nil {
		return Request{}, err
	}

	var r Request
	err = json.Unmarshal(resp, &r)
	if err != nil {
		return Request{}, err
	}

	return r, nil
}

// requestFeedResponse is the response for the requests feed endpoint.
type requestFeedResponse struct {
	Next map[string]string
	Data []Request
}

// GetRequestFeed gets the request feed for the site.
func (sc *Client) GetRequestFeed(corpName, siteName string, query url.Values) (next string, requests []Request, err error) {
	url := fmt.Sprintf("/v0/corps/%s/sites/%s/feed/requests", corpName, siteName)
	if query.Encode() != "" {
		url += "?" + query.Encode()
	}
	resp, err := sc.doRequest("GET", url, "")
	if err != nil {
		return "", []Request{}, err
	}

	var r requestFeedResponse
	err = json.Unmarshal(resp, &r)
	if err != nil {
		return "", []Request{}, err
	}

	return r.Next["uri"], r.Data, nil
}

// ListIP is a whitelisted or blacklisted IP address.
type ListIP struct {
	ID        string
	Source    string
	Expires   time.Time `json:"omitempty"`
	Note      string
	CreatedBy string
	Created   time.Time
}

// whitelistResponse is the response for the whitelist endpoint.
type whitelistResponse struct {
	Data []ListIP
}

// ListWhitelistIPs lists whitelisted IP addresses.
func (sc *Client) ListWhitelistIPs(corpName, siteName string) ([]ListIP, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites/%s/whitelist", corpName, siteName), "")
	if err != nil {
		return []ListIP{}, err
	}

	var wr whitelistResponse
	err = json.Unmarshal(resp, &wr)
	if err != nil {
		return []ListIP{}, err
	}

	return wr.Data, nil
}

// ListIPBody is the body for adding an IP to the whitelist or blacklist.
type ListIPBody struct {
	Source  string    `json:"source"`
	Note    string    `json:"note"`
	Expires time.Time `json:"expires,omitempty"`
}

// MarshalJSON is a custom JSON marshal method for ListIPBody
// so that Expires can be formatted as RFC3339
func (b ListIPBody) MarshalJSON() ([]byte, error) {
	var expires string
	if (b.Expires != time.Time{}) {
		expires = b.Expires.Format(time.RFC3339)
	}

	return json.Marshal(struct {
		Source  string `json:"source"`
		Note    string `json:"note"`
		Expires string `json:"expires,omitempty"`
	}{
		Source:  b.Source,
		Note:    b.Note,
		Expires: expires,
	})
}

// AddWhitelistIP adds an IP address to the whitelist.
func (sc *Client) AddWhitelistIP(corpName, siteName string, body ListIPBody) (ListIP, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return ListIP{}, err
	}

	resp, err := sc.doRequest("POST", fmt.Sprintf("/v0/corps/%s/sites/%s/whitelist", corpName, siteName), string(b))
	if err != nil {
		return ListIP{}, err
	}

	var ip ListIP
	err = json.Unmarshal(resp, &ip)
	if err != nil {
		return ListIP{}, err
	}

	return ip, nil
}

// DeleteWhitelistIP deletes a whitelisted IP by id.
func (sc *Client) DeleteWhitelistIP(corpName, siteName, id string) error {
	_, err := sc.doRequest("DELETE", fmt.Sprintf("/v0/corps/%s/sites/%s/whitelist/%s", corpName, siteName, id), "")

	return err
}

// blacklistResponse is the response for the blacklist endpoint.
type blacklistResponse struct {
	Data []ListIP
}

// ListBlacklistIPs lists blacklisted IP addresses.
func (sc *Client) ListBlacklistIPs(corpName, siteName string) ([]ListIP, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites/%s/blacklist", corpName, siteName), "")
	if err != nil {
		return []ListIP{}, err
	}

	var br blacklistResponse
	err = json.Unmarshal(resp, &br)
	if err != nil {
		return []ListIP{}, err
	}

	return br.Data, nil
}

// AddBlacklistIP adds an IP address to the blacklist.
func (sc *Client) AddBlacklistIP(corpName, siteName string, body ListIPBody) (ListIP, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return ListIP{}, err
	}

	resp, err := sc.doRequest("POST", fmt.Sprintf("/v0/corps/%s/sites/%s/blacklist", corpName, siteName), string(b))
	if err != nil {
		return ListIP{}, err
	}

	var ip ListIP
	err = json.Unmarshal(resp, &ip)
	if err != nil {
		return ListIP{}, err
	}

	return ip, nil
}

// DeleteBlacklistIP deletes a blacklisted IP by id.
func (sc *Client) DeleteBlacklistIP(corpName, siteName, id string) error {
	_, err := sc.doRequest("DELETE", fmt.Sprintf("/v0/corps/%s/sites/%s/blacklist/%s", corpName, siteName, id), "")

	return err
}

// Redaction contains the data for a privacy redaction
type Redaction struct {
	ID            string
	Field         string
	RedactionType int
	CreatedBy     string
	Created       time.Time
}

// redactionsResponse is the response for the list redactions endpoint
type redactionsResponse struct {
	Data []Redaction
}

// ListRedactions lists redactions.
func (sc *Client) ListRedactions(corpName, siteName string) ([]Redaction, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites/%s/redactions", corpName, siteName), "")
	if err != nil {
		return []Redaction{}, err
	}

	var rr redactionsResponse
	err = json.Unmarshal(resp, &rr)
	if err != nil {
		return []Redaction{}, err
	}

	return rr.Data, nil
}

// RedactionBody is the body for adding a redaction.
// Type of redaction (0: Request Parameter, 1: Request Header, 2: Response Header)
type RedactionBody struct {
	Field         string `json:"field"`
	RedactionType int    `json:"redactionType"`
}

// AddRedaction adds a redaction.
func (sc *Client) AddRedaction(corpName, siteName string, body RedactionBody) ([]Redaction, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return []Redaction{}, err
	}

	resp, err := sc.doRequest("POST", fmt.Sprintf("/v0/corps/%s/sites/%s/redactions", corpName, siteName), string(b))
	if err != nil {
		return []Redaction{}, err
	}

	var r redactionsResponse
	err = json.Unmarshal(resp, &r)
	if err != nil {
		return []Redaction{}, err
	}

	return r.Data, nil
}

// UpdateRedactionBody is the body for updating an integration.
type UpdateRedactionBody struct {
	Field         string `json:"field,omitempty"`
	RedactionType int    `json:"redactionType,omitempty"`
}

// UpdateRedaction updates a redaction by id.
func (sc *Client) UpdateRedaction(corpName, siteName, id string, body UpdateRedactionBody) (Redaction, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return Redaction{}, err
	}

	resp, err := sc.doRequest("PATCH", fmt.Sprintf("/v0/corps/%s/sites/%s/redactions/%s", corpName, siteName, id), string(b))
	if err != nil {
		return Redaction{}, err
	}

	var r Redaction
	err = json.Unmarshal(resp, &r)
	if err != nil {
		return Redaction{}, err
	}

	return r, err
}

// GetRedaction gets a redaction by id.
func (sc *Client) GetRedaction(corpName, siteName, id string) (Redaction, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites/%s/redactions/%s", corpName, siteName, id), "")
	if err != nil {
		return Redaction{}, err
	}

	var r Redaction
	err = json.Unmarshal(resp, &r)
	if err != nil {
		return Redaction{}, err
	}

	return r, nil
}

// DeleteRedaction deletes a redaction by id.
func (sc *Client) DeleteRedaction(corpName, siteName, id string) error {
	_, err := sc.doRequest("DELETE", fmt.Sprintf("/v0/corps/%s/sites/%s/redactions/%s", corpName, siteName, id), "")

	return err
}

// Integration contains the data for an integration
type Integration struct {
	ID        string
	Name      string
	Type      string
	URL       string
	Events    []string
	Active    bool
	Note      string
	CreatedBy string
	Created   time.Time
}

// integrationsResponse is the response for the list integrations endpoint
type integrationsResponse struct {
	Data []Integration
}

// ListIntegrations lists integrations.
func (sc *Client) ListIntegrations(corpName, siteName string) ([]Integration, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites/%s/integrations", corpName, siteName), "")
	if err != nil {
		return []Integration{}, err
	}

	var ir integrationsResponse
	err = json.Unmarshal(resp, &ir)
	if err != nil {
		return []Integration{}, err
	}

	return ir.Data, nil
}

// IntegrationBody is the body for adding an integration.
type IntegrationBody struct {
	URL    string   `json:"url"`
	Type   string   `json:"type"`
	Events []string `json:"events"`
}

// AddIntegration adds an integration.
func (sc *Client) AddIntegration(corpName, siteName string, body IntegrationBody) ([]Integration, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return []Integration{}, err
	}

	resp, err := sc.doRequest("POST", fmt.Sprintf("/v0/corps/%s/sites/%s/integrations", corpName, siteName), string(b))
	if err != nil {
		return []Integration{}, err
	}

	var ir integrationsResponse
	err = json.Unmarshal(resp, &ir)
	if err != nil {
		return []Integration{}, err
	}

	return ir.Data, nil
}

// GetIntegration gets an integration by id.
func (sc *Client) GetIntegration(corpName, siteName, id string) (Integration, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites/%s/integrations/%s", corpName, siteName, id), "")
	if err != nil {
		return Integration{}, err
	}

	var i Integration
	err = json.Unmarshal(resp, &i)
	if err != nil {
		return Integration{}, err
	}

	return i, nil
}

// UpdateIntegrationBody is the body for updating an integration.
type UpdateIntegrationBody struct {
	URL    string   `json:"url,omitempty"`
	Events []string `json:"smallIconURI,omitempty"`
}

// UpdateIntegration updates an integration by id.
func (sc *Client) UpdateIntegration(corpName, siteName, id string, body UpdateIntegrationBody) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}

	_, err = sc.doRequest("PATCH", fmt.Sprintf("/v0/corps/%s/sites/%s/integrations/%s", corpName, siteName, id), string(b))
	return err
}

// DeleteIntegration deletes a redaction by id.
func (sc *Client) DeleteIntegration(corpName, siteName, id string) error {
	_, err := sc.doRequest("DELETE", fmt.Sprintf("/v0/corps/%s/sites/%s/integrations/%s", corpName, siteName, id), "")

	return err
}

// Param is a whitelisted parameter.
type Param struct {
	ID        string
	Name      string
	Type      string
	Note      string
	CreatedBy string
	Created   time.Time
}

// paramsResponse is the response for the whitelisted params endpoint.
type paramsResponse struct {
	Data []Param
}

// ListParams lists whitelisted parameters.
func (sc *Client) ListParams(corpName, siteName string) ([]Param, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites/%s/paramwhitelist", corpName, siteName), "")
	if err != nil {
		return []Param{}, err
	}

	var pr paramsResponse
	err = json.Unmarshal(resp, &pr)
	if err != nil {
		return []Param{}, err
	}

	return pr.Data, nil
}

// ParamBody is the body for adding a whitelisted parameter.
type ParamBody struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Note string `json:"note"`
}

// AddParam adds a whitelisted parameter.
func (sc *Client) AddParam(corpName, siteName string, body ParamBody) ([]Param, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return []Param{}, err
	}

	resp, err := sc.doRequest("POST", fmt.Sprintf("/v0/corps/%s/sites/%s/paramwhitelist", corpName, siteName), string(b))
	if err != nil {
		return []Param{}, err
	}

	var pr paramsResponse
	err = json.Unmarshal(resp, &pr)
	if err != nil {
		return []Param{}, err
	}

	return pr.Data, nil
}

// GetParam gets a whitelisted param by id.
func (sc *Client) GetParam(corpName, siteName, id string) (Param, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites/%s/paramwhitelist/%s", corpName, siteName, id), "")
	if err != nil {
		return Param{}, err
	}

	var p Param
	err = json.Unmarshal(resp, &p)
	if err != nil {
		return Param{}, err
	}

	return p, nil
}

// DeleteParam deletes a whitelisted parameter by id.
func (sc *Client) DeleteParam(corpName, siteName, id string) error {
	_, err := sc.doRequest("DELETE", fmt.Sprintf("/v0/corps/%s/sites/%s/paramwhitelist/%s", corpName, siteName, id), "")

	return err
}

// Path is a whitelisted path.
type Path struct {
	ID        string
	Path      string
	Note      string
	CreatedBy string
	Created   time.Time
}

// pathsResponse is the response for the whitelisted paths endpoint.
type pathsResponse struct {
	Data []Path
}

// ListPaths lists whitelisted paths.
func (sc *Client) ListPaths(corpName, siteName string) ([]Path, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites/%s/pathwhitelist", corpName, siteName), "")
	if err != nil {
		return []Path{}, err
	}

	var pr pathsResponse
	err = json.Unmarshal(resp, &pr)
	if err != nil {
		return []Path{}, err
	}

	return pr.Data, nil
}

// PathBody is the body for creating a whitelisted path.
type PathBody struct {
	Path string `json:"path"`
	Note string `json:"note"`
}

// AddPath adds a whitelisted path.
func (sc *Client) AddPath(corpName, siteName string, body PathBody) ([]Path, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return []Path{}, err
	}

	resp, err := sc.doRequest("POST", fmt.Sprintf("/v0/corps/%s/sites/%s/pathwhitelist", corpName, siteName), string(b))
	if err != nil {
		return []Path{}, err
	}

	var pr pathsResponse
	err = json.Unmarshal(resp, &pr)
	if err != nil {
		return []Path{}, err
	}

	return pr.Data, nil
}

// GetPath gets a whitelisted path by id.
func (sc *Client) GetPath(corpName, siteName, id string) (Path, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites/%s/pathwhitelist/%s", corpName, siteName, id), "")
	if err != nil {
		return Path{}, err
	}

	var p Path
	err = json.Unmarshal(resp, &p)
	if err != nil {
		return Path{}, err
	}

	return p, nil
}

// DeletePath deletes a whitelisted path by id.
func (sc *Client) DeletePath(corpName, siteName, id string) error {
	_, err := sc.doRequest("DELETE", fmt.Sprintf("/v0/corps/%s/sites/%s/pathwhitelist/%s", corpName, siteName, id), "")

	return err
}

// ListSiteActivity lists activity events for a given site.
func (sc *Client) ListSiteActivity(corpName, siteName string, limit, page int) ([]ActivityEvent, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites/%s/activity?limit=%d&page=%d", corpName, siteName, limit, page), "")
	if err != nil {
		return []ActivityEvent{}, err
	}

	var ar activityResponse
	err = json.Unmarshal(resp, &ar)
	if err != nil {
		return []ActivityEvent{}, err
	}

	return ar.Data, nil
}

// HeaderLink contains the data for a response or request header link
type HeaderLink struct {
	ID        string
	Type      string
	Name      string
	LinkName  string
	Link      string
	CreatedBy string
	Created   time.Time
}

// headerLinksResponse is the response for the list header links endpoint
type headerLinksResponse struct {
	Data []HeaderLink
}

// ListHeaderLinks lists header links.
func (sc *Client) ListHeaderLinks(corpName, siteName string) ([]HeaderLink, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites/%s/headerLinks", corpName, siteName), "")
	if err != nil {
		return []HeaderLink{}, err
	}

	var hr headerLinksResponse
	err = json.Unmarshal(resp, &hr)
	if err != nil {
		return []HeaderLink{}, err
	}

	return hr.Data, nil
}

// HeaderLinkBody is the body for creating a header link.
type HeaderLinkBody struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	LinkName string `json:"linkName"`
	Link     string `json:"link"`
}

// AddHeaderLink adds a header link.
func (sc *Client) AddHeaderLink(corpName, siteName string, body HeaderLinkBody) ([]HeaderLink, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return []HeaderLink{}, err
	}

	resp, err := sc.doRequest("POST", fmt.Sprintf("/v0/corps/%s/sites/%s/pathwhitelist", corpName, siteName), string(b))
	if err != nil {
		return []HeaderLink{}, err
	}

	var hr headerLinksResponse
	err = json.Unmarshal(resp, &hr)
	if err != nil {
		return []HeaderLink{}, err
	}

	return hr.Data, nil
}

// GetHeaderLink gets a header link by id.
func (sc *Client) GetHeaderLink(corpName, siteName, id string) (HeaderLink, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites/%s/headerLinks/%s", corpName, siteName, id), "")
	if err != nil {
		return HeaderLink{}, err
	}

	var h HeaderLink
	err = json.Unmarshal(resp, &h)
	if err != nil {
		return HeaderLink{}, err
	}

	return h, nil
}

// DeleteHeaderLink deletes a header link by id.
func (sc *Client) DeleteHeaderLink(corpName, siteName, id string) error {
	_, err := sc.doRequest("DELETE", fmt.Sprintf("/v0/corps/%s/sites/%s/headerLinks/%s", corpName, siteName, id), "")

	return err
}

type site struct {
	Name string `json:"name"`
}

// SiteMembership contains the data needed for inviting a member to a site.
type SiteMembership struct {
	Site site `json:"site"`
	Role Role `json:"role"`
}

// NewSiteMembership returns a new site membership object for the given
// site name and role.
func NewSiteMembership(name string, role Role) SiteMembership {
	return SiteMembership{
		Site: site{Name: name},
		Role: role,
	}
}

// SiteMemberUser is the embedded user object in the site members response.
type SiteMemberUser struct {
	Name   string
	Email  string
	Status string
}

// SiteMember contains the data for a site member
type SiteMember struct {
	User SiteMemberUser
	Role Role
}

// siteMembersResponse is the response for the list site members endpoint
type siteMembersResponse struct {
	Data []SiteMember
}

// ListSiteMembers lists site members.
func (sc *Client) ListSiteMembers(corpName, siteName string) ([]SiteMember, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites/%s/members", corpName, siteName), "")
	if err != nil {
		return []SiteMember{}, err
	}

	var sr siteMembersResponse
	err = json.Unmarshal(resp, &sr)
	if err != nil {
		return []SiteMember{}, err
	}

	return sr.Data, nil
}

// GetSiteMember gets a site member by email.
func (sc *Client) GetSiteMember(corpName, siteName, email string) (SiteMember, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites/%s/members/%s", corpName, siteName, email), "")
	if err != nil {
		return SiteMember{}, err
	}

	var s SiteMember
	err = json.Unmarshal(resp, &s)
	if err != nil {
		return SiteMember{}, err
	}

	return s, nil
}

// SiteMemberBody is the body for updating or inviting a site member.
type SiteMemberBody struct {
	Role Role `json:"role"`
}

// SiteMemberResponse is the response for updating or inviting a site member.
type SiteMemberResponse struct {
	Email  string
	Role   Role
	Status string
}

// UpdateSiteMember updates a site member by email.
func (sc *Client) UpdateSiteMember(corpName, siteName, email string, body SiteMemberBody) (SiteMemberResponse, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return SiteMemberResponse{}, err
	}

	resp, err := sc.doRequest("PATCH", fmt.Sprintf("/v0/corps/%s/sites/%s/members/%s", corpName, siteName, email), string(b))
	if err != nil {
		return SiteMemberResponse{}, err
	}

	var sm SiteMemberResponse
	err = json.Unmarshal(resp, &sm)
	if err != nil {
		return SiteMemberResponse{}, err
	}

	return sm, nil
}

// DeleteSiteMember deletes a site member by email.
func (sc *Client) DeleteSiteMember(corpName, siteName, email string) error {
	_, err := sc.doRequest("DELETE", fmt.Sprintf("/v0/corps/%s/sites/%s/members/%s", corpName, siteName, email), "")

	return err
}

// InviteSiteMember invites a site member by email.
func (sc *Client) InviteSiteMember(corpName, siteName, email string, body SiteMemberBody) (SiteMemberResponse, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return SiteMemberResponse{}, err
	}

	resp, err := sc.doRequest("POST", fmt.Sprintf("/v0/corps/%s/sites/%s/members/%s/invite", corpName, siteName, email), string(b))
	if err != nil {
		return SiteMemberResponse{}, err
	}

	var sm SiteMemberResponse
	err = json.Unmarshal(resp, &sm)
	if err != nil {
		return SiteMemberResponse{}, err
	}

	return sm, nil
}

// SiteMonitor is a monitor URL for a site.
type SiteMonitor struct {
	ID        string
	URL       string
	Share     bool
	CreatedBy string
	Created   time.Time
}

// GetSiteMonitor gets the site monitor URL.
func (sc *Client) GetSiteMonitor(corpName, siteName, email string) (SiteMonitor, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites/%s/monitors", corpName, siteName), "")
	if err != nil {
		return SiteMonitor{}, err
	}

	var s SiteMonitor
	err = json.Unmarshal(resp, &s)
	if err != nil {
		return SiteMonitor{}, err
	}

	return s, nil
}

// GenerateSiteMonitor generates a site monitor URL.
func (sc *Client) GenerateSiteMonitor(corpName, siteName string) (SiteMonitor, error) {
	resp, err := sc.doRequest("POST", fmt.Sprintf("/v0/corps/%s/sites/%s/monitors", corpName, siteName), "")
	if err != nil {
		return SiteMonitor{}, err
	}

	var s SiteMonitor
	err = json.Unmarshal(resp, &s)
	if err != nil {
		return SiteMonitor{}, err
	}

	return s, nil
}

// EnableSiteMonitor enables the site monitor URL for a given site.
func (sc *Client) EnableSiteMonitor(corpName, siteName string) error {
	_, err := sc.doRequest("POST", fmt.Sprintf("/v0/corps/%s/sites/%s/monitors/enable", corpName, siteName), "")

	return err
}

// DisableSiteMonitor disables the site monitor URL for a given site.
func (sc *Client) DisableSiteMonitor(corpName, siteName string) error {
	_, err := sc.doRequest("POST", fmt.Sprintf("/v0/corps/%s/sites/%s/monitors/disable", corpName, siteName), "")

	return err
}

// Agent contains the data for an agent
type Agent struct {
	AgentActive                 bool      `json:"agent.active"`
	AgentAddr                   string    `json:"agent.addr"`
	AgentArgs                   string    `json:"agent.args"`
	AgentBuildID                string    `json:"agent.build_id"`
	AgentCGroup                 string    `json:"agent.cgroup"`
	AgentConnectionsDropped     int       `json:"agent.connections_dropped"`
	AgentConnectionsOpen        int       `json:"agent.connections_open"`
	AgentConnectionsTotal       int       `json:"agent.connections_total"`
	AgentCurrentRequests        int       `json:"agent.current_requests"`
	AgentDecisionTime50th       float64   `json:"agent.decision_time_50th"`
	AgentDecisionTime95th       float64   `json:"agent.decision_time_95th"`
	AgentDecisionTime99th       float64   `json:"agent.decision_time_99th"`
	AgentEnabled                bool      `json:"agent.enabled"`
	AgentLastRuleUpdate         time.Time `json:"agent.last_rule_update"`
	AgentLastSeen               time.Time `json:"agent.last_seen"`
	AgentLatencyTime50th        float64   `json:"agent.latency_time_50th"`
	AgentLatencyTime95th        float64   `json:"agent.latency_time_95th"`
	AgentLatencyTime99th        float64   `json:"agent.latency_time_99th"`
	AgentMaxProcs               int       `json:"agent.max_procs"`
	AgentName                   string    `json:"agent.name"`
	AgentPID                    int       `json:"agent.pid"`
	AgentReadBytes              int       `json:"agent.read_bytes"`
	AgentRPCPostrequest         int       `json:"agent.rpc_postrequest"`
	AgentRPCPrerequest          int       `json:"agent.rpc_prerequest"`
	AgentRPCUpdaterequest       int       `json:"agent.rpc_updaterequest"`
	AgentRuleUpdates            int       `json:"agent.rule_updates"`
	AgentStatus                 string    `json:"agent.status"`
	AgentTimestamp              int       `json:"agent.timestamp"`
	AgentTimezone               string    `json:"agent.timezone"`
	AgentTimezoneOffset         int       `json:"agent.timezone_offset"`
	AgentUploadMetadataFailures int       `json:"agent.upload_metadata_failures"`
	AgentUploadSize             int       `json:"agent.upload_size"`
	AgentUptime                 int       `json:"agent.uptime"`
	AgentVersion                string    `json:"agent.version"`
	AgentVersionsBehind         int       `json:"agent.versions_behind"`
	AgentWriteBytes             int       `json:"agent.write_bytes"`
	HostAgentCPU                float64   `json:"host.agent_cpu"`
	HostArchitecture            string    `json:"host.architecture"`
	HostClockSkew               int       `json:"host.clock_skew"`
	HostCPU                     float64   `json:"host.cpu"`
	HostCPUMhz                  int       `json:"host.cpu_mhz"`
	HostInstanceType            string    `json:"host.instance_type"`
	HostNumCPU                  int       `json:"host.num_cpu"`
	HostOS                      string    `json:"host.os"`
	HostRemoteAddr              string    `json:"host.remote_addr"`
	ModuleDetected              bool      `json:"module.detected"`
	ModuleServer                string    `json:"module.server"`
	ModuleType                  string    `json:"module.type"`
	ModuleVersion               string    `json:"module.version"`
	ModuleVersionsBehind        int       `json:"module.versions_behind"`
	RuntimeGcPauseMillis        float64   `json:"runtime.gc_pause_millis"`
	RuntimeMemSize              int       `json:"mem_size"`
	RuntimeNumGc                int       `json:"num_gc"`
	RuntimeNumGoroutines        int       `json:"num_goroutines"`
}

// agentsResponse is the response for the list agents endpoint
type agentsResponse struct {
	Data []Agent
}

// ListAgents lists agents for a given corp and site.
func (sc *Client) ListAgents(corpName, siteName string) ([]Agent, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites/%s/agents", corpName, siteName), "")
	if err != nil {
		return []Agent{}, err
	}

	var ar agentsResponse
	err = json.Unmarshal(resp, &ar)
	if err != nil {
		return []Agent{}, err
	}

	return ar.Data, nil
}

// GetAgent gets an agent by name.
func (sc *Client) GetAgent(corpName, siteName, agentName string) (Agent, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites/%s/agents/%s", corpName, siteName, agentName), "")
	if err != nil {
		return Agent{}, err
	}

	var agent Agent
	err = json.Unmarshal(resp, &agent)
	if err != nil {
		return Agent{}, err
	}

	return agent, nil
}

// AgentLog is an agent log
type AgentLog struct {
	Hostname  string    `json:"hostName"`
	LogLevel  string    `json:"logLevel"`
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"createdAt"`
}

// agentLogsResponse is the response for the agent logs endpoint
type agentLogsResponse struct {
	Corp string
	Site string
	Logs []AgentLog
}

// GetAgentLogs gets agent logs for a given agent.
func (sc *Client) GetAgentLogs(corpName, siteName, agentName string) ([]AgentLog, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites/%s/agents/%s/logs", corpName, siteName, agentName), "")
	if err != nil {
		return []AgentLog{}, err
	}

	var alr agentLogsResponse
	err = json.Unmarshal(resp, &alr)
	if err != nil {
		return []AgentLog{}, err
	}

	return alr.Logs, nil
}

// SuspiciousIP is a suspicious IP.
type SuspiciousIP struct {
	Source            string
	Percent           int
	RemoteCountryCode string    `json:"remoteCountryCode"`
	RemoteHostname    string    `json:"remoteHostname"`
	TagName           string    `json:"tagName"`
	ShortName         string    `json:"shortName"`
	IntervalStart     time.Time `json:"interval_start"`
	Timestamp         time.Time
}

// suspiciousIPSResponse is the response for the suspicious IPs endpoint.
type suspiciousIPSResponse struct {
	Data []SuspiciousIP
}

// ListSuspiciousIPs lists suspicious IPs.
func (sc *Client) ListSuspiciousIPs(corpName, siteName string) ([]SuspiciousIP, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites/%s/suspiciousIPs", corpName, siteName), "")
	if err != nil {
		return []SuspiciousIP{}, err
	}

	var sr suspiciousIPSResponse
	err = json.Unmarshal(resp, &sr)
	if err != nil {
		return []SuspiciousIP{}, err
	}

	return sr.Data, nil
}

// TopAttack is a top attack.
type TopAttack struct {
	Value string
	Label string
	Count int
}

// topAttacksResponse is the response for the top attacks endpoint.
type topAttacksResponse struct {
	Data []TopAttack
}

// ListTopAttacks lists top attacks.
func (sc *Client) ListTopAttacks(corpName, siteName string, query url.Values) ([]TopAttack, error) {
	url := fmt.Sprintf("/v0/corps/%s/sites/%s/top/attacks", corpName, siteName)
	if query.Encode() != "" {
		url += "?" + query.Encode()
	}
	resp, err := sc.doRequest("GET", url, "")
	if err != nil {
		return []TopAttack{}, err
	}

	var tr topAttacksResponse
	err = json.Unmarshal(resp, &tr)
	if err != nil {
		return []TopAttack{}, err
	}

	return tr.Data, nil
}

// Timeseries contains timeseries request info.
type Timeseries struct {
	Type         string
	From         int
	Until        int
	Inc          int
	Data         []int
	SummaryCount int
	TotalPoints  int
}

type timeseriesResponse struct {
	Data []Timeseries
}

// GetTimeseries gets timeseries request info.
func (sc *Client) GetTimeseries(corpName, siteName string, query url.Values) ([]Timeseries, error) {
	url := fmt.Sprintf("/v0/corps/%s/sites/%s/timeseries/requests", corpName, siteName)
	if query.Encode() != "" {
		url += "?" + query.Encode()
	}
	resp, err := sc.doRequest("GET", url, "")
	if err != nil {
		return []Timeseries{}, err
	}

	var t timeseriesResponse
	err = json.Unmarshal(resp, &t)
	if err != nil {
		return []Timeseries{}, err
	}

	return t.Data, nil
}

type healthCheck struct {
	Name   string
	Status string
	Data   map[string]interface{}
}

type siteHealth struct {
	SiteName     string
	DisplayName  string
	Grade        string
	AgentsCount  int
	ModulesCount int
	HealthChecks []healthCheck
}

// HealthReport is the response for the health check report endpoint.
type HealthReport struct {
	CorpName     string
	Grade        string
	SiteLimit    int
	UsersCount   int
	HealthChecks []healthCheck
	SiteMetrics  []siteHealth
}

// GetHealthReport gets the health report for a given corp by name.
func (sc *Client) GetHealthReport(corpName string) (HealthReport, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/health", corpName), "")
	if err != nil {
		return HealthReport{}, err
	}

	var h HealthReport
	err = json.Unmarshal(resp, &h)
	if err != nil {
		return HealthReport{}, err
	}

	return h, nil
}
