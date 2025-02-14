// Package sigsci provides methods for interacting with the Signal Sciences API.
package sigsci

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// apiURL is the base URL for API requests
var apiURL = "https://dashboard.signalsciences.net/api"

// SetAPIUrl allows developer to point to a different endpoint in special circumstances (e.g. during testing)
func SetAPIUrl(theURL string) {
	apiURL = theURL
}

// Client is the API client
type Client struct {
	email     string
	token     string
	fastlyKey string
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

func (c *Client) SetFastlyKey(fastlyKey string) {
	c.fastlyKey = fastlyKey
}

// NewTokenClient creates a Client using token authentication
func NewTokenClient(email, token string) Client {
	return Client{
		email: email,
		token: token,
	}
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
	resp, err := sc.doRequestDetailed(method, url, reqBody)
	if err != nil {
		return []byte{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
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
		switch resp.StatusCode {
		case http.StatusOK, http.StatusNoContent:
		default:
			return body, errMsg(body)
		}
	case "PUT":
		fallthrough
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
	RoleNoAccess = Role("none")
	RoleUnknown  = Role("unknown")
	RoleOwner    = Role("owner")
	RoleAdmin    = Role("admin")
	RoleUser     = Role("user")
	RoleObserver = Role("observer")

	// Deprecated corp/site roles
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

type ClientIPRules []struct {
	Header string `json:"header"`
}

// Site contains details for a site.
type Site struct {
	Name                 string
	DisplayName          string
	AgentLevel           string
	BlockHTTPCode        int
	BlockDurationSeconds int
	BlockRedirectURL     string
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
	AgentAnonMode        string
	ClientIPRules        ClientIPRules
	AttackThresholds     []AttackThreshold
	ImmediateBlock       bool
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
	AgentLevel           string            `json:"agentLevel,omitempty"`
	AgentAnonMode        string            `json:"agentAnonMode"`
	AttackThresholds     []AttackThreshold `json:"attackThresholds,omitempty"` // Slice of AttackThreshold
	BlockDurationSeconds int               `json:"blockDurationSeconds,omitempty"`
	BlockHTTPCode        int               `json:"blockHTTPCode,omitempty"`
	BlockRedirectURL     string            `json:"blockRedirectURL,omitempty"`
	ClientIPRules        ClientIPRules     `json:"clientIPRules"`
	DisplayName          string            `json:"displayName,omitempty"`
	ImmediateBlock       bool              `json:"immediateBlock"` // Enable immediate blocking
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

// CustomAlert is the body for creating a custom alert.
type CustomAlert struct {
	ID                   string    `json:"id,omitempty"` // Site-specific unique ID of the alert
	SiteID               string    `json:"siteID,omitempty"`
	TagName              string    `json:"tagName,omitempty"`              // The name of the tag whose occurrences the alert is watching. Must match an existing tag
	LongName             string    `json:"longName,omitempty"`             // A human readable description of the alert. Must be between 3 and 25 characters.
	Interval             int       `json:"interval"`                       // The number of minutes of past traffic to examine. Must be 1, 10 or 60.
	Threshold            int       `json:"threshold"`                      // The number of occurrences of the tag in the interval needed to trigger the alert.
	BlockDurationSeconds int       `json:"blockDurationSeconds,omitempty"` // The number of seconds this alert is active. empty means default value
	Enabled              bool      `json:"enabled"`                        // A flag to toggle this alert.
	Action               string    `json:"action,omitempty"`               // A flag that describes what happens when the alert is triggered. 'info' creates an incident in the dashboard. 'flagged' creates an incident and blocks traffic for 24 hours.
	Type                 string    `json:"type,omitempty"`                 // Type of alert (siteAlert, template, rateLimit, siteMetric)
	SkipNotifications    bool      `json:"skipNotifications"`              // A flag to disable external notifications - slack, webhooks, emails, etc.
	FieldName            string    `json:"fieldName,omitempty"`
	CreatedBy            string    `json:"createdBy,omitempty"` // The email of the user that created the alert
	Created              time.Time `json:"created,omitempty"`   // RFC3339 date time
	Operator             string    `json:"operator,omitempty"`
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
	TagName              string `json:"tagName"`
	LongName             string `json:"longName"`
	Interval             int    `json:"interval"`
	Threshold            int    `json:"threshold"`
	Enabled              bool   `json:"enabled"`
	Action               string `json:"action"`
	SkipNotifications    bool   `json:"skipNotifications"`
	BlockDurationSeconds int    `json:"blockDurationSeconds,omitempty"`
	Operator             string `json:"operator,omitempty"`
	FieldName            string `json:"fieldName,omitempty"`
}

// CreateCustomAlert creates a custom alert.
func (sc *Client) CreateCustomAlert(corpName, siteName string, body CustomAlertBody) (CustomAlert, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return CustomAlert{}, err
	}

	resp, err := sc.doRequest("POST", fmt.Sprintf("/v0/corps/%s/sites/%s/alerts", corpName, siteName), string(b))
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
	Type     string `json:"type"`
	Location string `json:"location"`
	Value    string `json:"value"`
	Detector string `json:"detector"`
}

// Request contains the data for a request
type Request struct {
	ID                string       `json:"id"`
	ServerHostname    string       `json:"serverHostname"`
	RemoteIP          string       `json:"remoteIP"`
	RemoteHostname    string       `json:"remoteHostname"`
	RemoteCountryCode string       `json:"remoteCountryCode"`
	UserAgent         string       `json:"userAgent"`
	Timestamp         time.Time    `json:"timestamp"`
	Method            string       `json:"method"`
	ServerName        string       `json:"serverName"`
	Protocol          string       `json:"protocol"`
	TLSProtocol       string       `json:"tlsProtocol"`
	TLSCipher         string       `json:"tlsCipher"`
	Scheme            string       `json:"scheme"`
	HeadersIn         [][]string   `json:"headersIn"`
	Path              string       `json:"path"`
	URI               string       `json:"uri"`
	ResponseCode      int          `json:"responseCode"`
	ResponseSize      int          `json:"responseSize"`
	ResponseMillis    int          `json:"responseMillis"`
	HeadersOut        [][]string   `json:"headersOut"`
	AgentResponseCode int          `json:"agentResponseCode"`
	Tags              []RequestTag `json:"tags"`
}

// requestsResponse is the response for the search requests endpoint
type requestsResponse struct {
	TotalCount int
	Next       map[string]string
	Data       []Request
}

// SearchRequests searches requests.
func (sc *Client) SearchRequests(corpName, siteName string, query url.Values) (totalCount int, next string, requests []Request, err error) {
	url := fmt.Sprintf("/v0/corps/%s/sites/%s/requests", corpName, siteName)
	if query.Encode() != "" {
		url += "?" + query.Encode()
	}
	resp, err := sc.doRequest("GET", url, "")
	if err != nil {
		return 0, "", []Request{}, err
	}

	var r requestsResponse
	err = json.Unmarshal(resp, &r)
	if err != nil {
		return 0, "", []Request{}, err
	}

	return r.TotalCount, r.Next["uri"], r.Data, nil
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
	URL    string            `json:"url"`
	Type   string            `json:"type"`
	Events []string          `json:"events"`
	Fields map[string]string `json:"fields,omitempty"`
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
	URL    string            `json:"url,omitempty"`
	Events []string          `json:"events,omitempty"`
	Fields map[string]string `json:"fields,omitempty"`
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

// AddCorpIntegration adds an integration.
func (sc *Client) AddCorpIntegration(corpName string, body IntegrationBody) (Integration, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return Integration{}, err
	}

	resp, err := sc.doRequest("POST", fmt.Sprintf("/v0/corps/%s/integrations", corpName), string(b))
	if err != nil {
		return Integration{}, err
	}

	var ir Integration
	err = json.Unmarshal(resp, &ir)
	if err != nil {
		return Integration{}, err
	}

	return ir, nil
}

// GetCorpIntegration gets an integration by id.
func (sc *Client) GetCorpIntegration(corpName, id string) (Integration, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/integrations/%s", corpName, id), "")
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

// UpdateCorpIntegration updates an integration by id.
func (sc *Client) UpdateCorpIntegration(corpName, id string, body UpdateIntegrationBody) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}

	_, err = sc.doRequest("PATCH", fmt.Sprintf("/v0/corps/%s/integrations/%s", corpName, id), string(b))
	return err
}

// DeleteCorpIntegration deletes a redaction by id.
func (sc *Client) DeleteCorpIntegration(corpName, id string) error {
	_, err := sc.doRequest("DELETE", fmt.Sprintf("/v0/corps/%s/integrations/%s", corpName, id), "")

	return err
}

// CloudWAFInstance contains the data for a Cloud WAF Instance read API call.
type CloudWAFInstance struct {
	CloudWAFInstanceBody
	ID         string                     `json:"id"`
	Deployment CloudWAFInstanceDeployment `json:"deployment"`
	CreatedBy  string                     `json:"createdBy"`
	Created    string                     `json:"created"`
	UpdatedBy  string                     `json:"updatedBy"`
}

// CloudWAFInstanceDeployment contains the data for a Cloud WAF instance eeployment.
type CloudWAFInstanceDeployment struct {
	Status    string                     `json:"status"`
	Message   string                     `json:"message"`
	EgressIPs []CloudWAFInstanceEgressIP `json:"egressIPs"`
	DNSEntry  string                     `json:"dnsEntry"`
}

// CloudWAFInstanceEgressIP contains the data for a Cloud WAF instance egress IP.
type CloudWAFInstanceEgressIP struct {
	IP        string `json:"ip"`
	Status    string `json:"status"`
	UpdatedAt string `json:"updatedAt"`
}

// CloudWAFInstanceBody is the body for adding or updating a Cloud WAF instance.
type CloudWAFInstanceBody struct {
	Name                    string                            `json:"name"`
	Description             string                            `json:"description"`
	Region                  string                            `json:"region"`
	TLSMinVersion           string                            `json:"tlsMinVersion"`
	UseUploadedCertificates bool                              `json:"useUploadedCertificates"`
	WorkspaceConfigs        []CloudWAFInstanceWorkspaceConfig `json:"workspaceConfigs"`
}

// CloudWAFInstanceWorkspaceConfig contains the data for a Cloud WAF instance workspace config.
type CloudWAFInstanceWorkspaceConfig struct {
	SiteName          string                           `json:"siteName"`
	InstanceLocation  string                           `json:"instanceLocation"`
	ClientIPHeader    string                           `json:"clientIPHeader"`
	ListenerProtocols []string                         `json:"listenerProtocols"`
	Routes            []CloudWAFInstanceWorkspaceRoute `json:"routes"`
}

// CloudWAFInstanceWorkspaceRoute contains the data for a Cloud WAF instance workspace route.
type CloudWAFInstanceWorkspaceRoute struct {
	// ID is the route's ID after being created. It should not be populated during
	// create but should be populated during update.
	ID                    string   `json:"id"`
	CertificateIDs        []string `json:"certificateIds"`
	Origin                string   `json:"origin"`
	Domains               []string `json:"domains"`
	ConnectionPooling     bool     `json:"connectionPooling"`
	PassHostHeader        bool     `json:"passHostHeader"`
	TLSHostOverride       bool     `json:"tlsHostOverride"`
	TLSInsecureSkipVerify bool     `json:"tlsInsecureSkipVerify"`
	TrustProxyHeaders     bool     `json:"trustProxyHeaders"`
}

// cloudWAFInstancesResponse is the response for the list cloudwafInstances endpoint.
type cloudWAFInstancesResponse struct {
	Data []CloudWAFInstance `json:"data"`
}

// ListCloudWAFInstances lists Cloud WAF instances.
func (sc *Client) ListCloudWAFInstances(corpName string) ([]CloudWAFInstance, error) {
	resp, err := sc.doRequest(http.MethodGet, fmt.Sprintf("/v0/corps/%s/cloudwafInstances", corpName), "")
	if err != nil {
		return []CloudWAFInstance{}, err
	}

	var cwr cloudWAFInstancesResponse
	err = json.Unmarshal(resp, &cwr)
	if err != nil {
		return []CloudWAFInstance{}, err
	}

	return cwr.Data, nil
}

// CreateCloudWAFInstance adds a Cloud WAF instance.
func (sc *Client) CreateCloudWAFInstance(corpName string, body CloudWAFInstanceBody) (CloudWAFInstance, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return CloudWAFInstance{}, err
	}

	resp, err := sc.doRequest(http.MethodPost, fmt.Sprintf("/v0/corps/%s/cloudwafInstances", corpName), string(b))
	if err != nil {
		return CloudWAFInstance{}, err
	}

	var cwr CloudWAFInstance
	return cwr, json.Unmarshal(resp, &cwr)
}

// GetCloudWAFInstance gets a Cloud WAF instance by id.
func (sc *Client) GetCloudWAFInstance(corpName, id string) (CloudWAFInstance, error) {
	resp, err := sc.doRequest(http.MethodGet, fmt.Sprintf("/v0/corps/%s/cloudwafInstances/%s", corpName, id), "")
	if err != nil {
		return CloudWAFInstance{}, err
	}

	var cwr CloudWAFInstance
	return cwr, json.Unmarshal(resp, &cwr)
}

// UpdateCloudWAFInstance updates a Cloud WAF instance by id.
func (sc *Client) UpdateCloudWAFInstance(corpName, id string, body CloudWAFInstanceBody) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}

	_, err = sc.doRequest(http.MethodPut, fmt.Sprintf("/v0/corps/%s/cloudwafInstances/%s", corpName, id), string(b))
	return err
}

// DeleteCloudWAFInstance deletes a Cloud WAF instance by id.
func (sc *Client) DeleteCloudWAFInstance(corpName, id string) error {
	_, err := sc.doRequest(http.MethodDelete, fmt.Sprintf("/v0/corps/%s/cloudwafInstances/%s", corpName, id), "")

	return err
}

// RestartCloudWAFInstance restarts a Cloud WAF instance by id.
func (sc *Client) RestartCloudWAFInstance(corpName, id string) error {
	_, err := sc.doRequest(http.MethodPost, fmt.Sprintf("/v0/corps/%s/cloudwafInstances/%s/restart", corpName, id), "")

	return err
}

// CloudWAFCertificate contains the data for a Cloud WAF Certificate read API call.
type CloudWAFCertificateBase struct {
	Name             string `json:"name"`
	CertificateBody  string `json:"certificateBody"`
	CertificateChain string `json:"certificateChain"`
}

type CloudWAFCertificate struct {
	CloudWAFCertificateBase
	ID                      string
	CommonName              string
	SubjectAlternativeNames []string
	Domains                 []string
	Fingerprint             string
	ExpiresAt               string
	Status                  string
	CreatedBy               string
	Created                 string
	UpdatedBy               string
	UpdatedAt               string
}

type UploadCloudWAFCertificateBody struct {
	CloudWAFCertificateBase
	PrivateKey string
}

type ResponseCloudWAFCertificateBody struct {
	ID string `json:"id"`
}

type UpdateCloudWAFCertificateBody struct {
	Name string `json:"name"`
}

type listCloudWAFCertificateResponse struct {
	Data []CloudWAFCertificate `json:"data"`
}

// ListCloudWAFCertificates lists Cloud WAF certificates.
func (sc *Client) ListCloudWAFCertificates(corpName string) ([]CloudWAFCertificate, error) {
	resp, err := sc.doRequest(http.MethodGet, fmt.Sprintf("/v0/corps/%s/cloudwafCerts", corpName), "")
	if err != nil {
		return []CloudWAFCertificate{}, err
	}

	var cwr listCloudWAFCertificateResponse
	err = json.Unmarshal(resp, &cwr)
	if err != nil {
		return []CloudWAFCertificate{}, err
	}

	return cwr.Data, nil
}

// UploadCloudWAFCertificate uploads a Cloud WAF certificate and private key.
func (sc *Client) UploadCloudWAFCertificate(corpName string, body UploadCloudWAFCertificateBody) (ResponseCloudWAFCertificateBody, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return ResponseCloudWAFCertificateBody{}, err
	}

	resp, err := sc.doRequest(http.MethodPost, fmt.Sprintf("/v0/corps/%s/cloudwafCerts", corpName), string(b))
	if err != nil {
		return ResponseCloudWAFCertificateBody{}, err
	}

	var cwr ResponseCloudWAFCertificateBody
	return cwr, json.Unmarshal(resp, &cwr)
}

// GetCloudWAFCertificate gets a Cloud WAF certificate by id.
func (sc *Client) GetCloudWAFCertificate(corpName, id string) (CloudWAFCertificate, error) {
	resp, err := sc.doRequest(http.MethodGet, fmt.Sprintf("/v0/corps/%s/cloudwafCerts/%s", corpName, id), "")
	if err != nil {
		return CloudWAFCertificate{}, err
	}

	var cwr CloudWAFCertificate
	return cwr, json.Unmarshal(resp, &cwr)
}

// UpdateCloudWAFCertificate updates a Cloud WAF certificate by id.
func (sc *Client) UpdateCloudWAFCertificate(corpName, id string, body UpdateCloudWAFCertificateBody) (CloudWAFCertificate, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return CloudWAFCertificate{}, err
	}

	bytes, err := sc.doRequest(http.MethodPut, fmt.Sprintf("/v0/corps/%s/cloudwafCerts/%s", corpName, id), string(b))
	if err != nil {
		return CloudWAFCertificate{}, err
	}
	var cwr CloudWAFCertificate
	return cwr, json.Unmarshal(bytes, &cwr)
}

// DeleteCloudWAFCertificate deletes a Cloud WAF certificate by id.
func (sc *Client) DeleteCloudWAFCertificate(corpName, id string) error {
	_, err := sc.doRequest(http.MethodDelete, fmt.Sprintf("/v0/corps/%s/cloudwafCerts/%s", corpName, id), "")

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

	resp, err := sc.doRequest("POST", fmt.Sprintf("/v0/corps/%s/sites/%s/headerLinks", corpName, siteName), string(b))
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

// siteMembersBody is the body for adding one or more existing users to a site.
type siteMembersBody struct {
	Members []string `json:"members"`
}

// AddSiteMembers adds one or more existing users to a site.
func (sc *Client) AddSiteMembers(corpName, siteName string, body siteMembersBody) ([]SiteMember, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return []SiteMember{}, err
	}

	resp, err := sc.doRequest("POST", fmt.Sprintf("/v0/corps/%s/sites/%s/members", corpName, siteName), string(b))
	if err != nil {
		return []SiteMember{}, err
	}

	var sm siteMembersResponse
	err = json.Unmarshal(resp, &sm)
	if err != nil {
		return []SiteMember{}, err
	}

	return sm.Data, nil
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

// SiteMemberBody is the body for inviting a user to a site.
type SiteMemberBody struct {
	Role Role `json:"role"`
}

// SiteMemberResponse is the response for inviting a user to a site.
type SiteMemberResponse struct {
	Email  string
	Role   Role
	Status string
}

// AddSiteMember adds an existing user to a site by email.
func (sc *Client) AddSiteMember(corpName, siteName, email string) (SiteMemberResponse, error) {
	resp, err := sc.doRequest("PATCH", fmt.Sprintf("/v0/corps/%s/sites/%s/members/%s", corpName, siteName, email), "")
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

// InviteSiteMember invites a new user to a site by email.
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

// SiteMonitorResp is the response from GET site monitor
type SiteMonitorResp struct {
	Data []SiteMonitor
}

// GetSiteMonitor gets the site monitor URL.
func (sc *Client) GetSiteMonitor(corpName, siteName, email string) ([]SiteMonitor, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites/%s/monitors", corpName, siteName), "")
	if err != nil {
		return []SiteMonitor{}, err
	}

	var s SiteMonitorResp
	err = json.Unmarshal(resp, &s)
	if err != nil {
		return []SiteMonitor{}, err
	}

	return s.Data, nil
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

// GenerateSiteMonitorDashboard generates a site monitor URL for a dashboard.
func (sc *Client) GenerateSiteMonitorDashboard(corpName, siteName, dashboard string) (SiteMonitor, error) {
	resp, err := sc.doRequest("POST", fmt.Sprintf("/v0/corps/%s/sites/%s/monitors?dashboardId=%s", corpName, siteName, dashboard), "")
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

// UpdateSiteMonitorBody is the body to update a site monitor
type UpdateSiteMonitorBody struct {
	ID    string `json:"id"`
	Share bool   `json:"share"`
}

// UpdateSiteMonitor updates a monitor in place
func (sc *Client) UpdateSiteMonitor(corpName, siteName, id string, body UpdateSiteMonitorBody) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}

	_, err = sc.doRequest("PUT", fmt.Sprintf("/v0/corps/%s/sites/%s/monitors/%s", corpName, siteName, id), string(b))

	return err
}

// DeleteSiteMonitor Deletes the site monitor URL for a given site.
func (sc *Client) DeleteSiteMonitor(corpName, siteName, id string) error {
	_, err := sc.doRequest("DELETE", fmt.Sprintf("/v0/corps/%s/sites/%s/monitors/%s", corpName, siteName, id), "")
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

// AttackThreshold
type AttackThreshold struct {
	Interval  int `json:"interval,omitempty"`  // Interval in minutes of threshold. Valid options 1, 10, 60
	Threshold int `json:"threshold,omitempty"` // Threshold from 1 - 10000
}

// CreateSiteBody is the structure required to create a Site.
type CreateSiteBody struct {
	Name                 string            `json:"name,omitempty"`                 // Identifying name of the site
	DisplayName          string            `json:"displayName,omitempty"`          // Display name of the site
	AgentLevel           string            `json:"agentLevel,omitempty"`           // Agent action level - 'block', 'log' or 'off'
	AgentAnonMode        string            `json:"agentAnonMode"`                  // Agent IP anonymization mode - 'EU' or ''
	BlockHTTPCode        int               `json:"blockHTTPCode,omitempty"`        // HTTP response code to send when traffic is being blocked
	BlockRedirectURL     string            `json:"blockRedirectURL,omitempty"`     // URL to redirect to when BlockHTTPCode is 301 or 302
	BlockDurationSeconds int               `json:"blockDurationSeconds,omitempty"` // Duration to block an IP in seconds
	ClientIPRules        ClientIPRules     `json:"clientIPRules"`                  // The specified header to assign client IPs to requests.
	AttackThresholds     []AttackThreshold `json:"attackThresholds,omitempty"`     // Slice of AttackThreshold
	ImmediateBlock       bool              `json:"immediateBlock"`                 // Enable immediate blocking
}

// CreateSite Creates a site in a corp.
func (sc *Client) CreateSite(corpName string, body CreateSiteBody) (Site, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return Site{}, err
	}

	resp, err := sc.doRequest("POST", fmt.Sprintf("/v0/corps/%s/sites", corpName), string(b))
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

// DeleteSite deletes the site
func (sc *Client) DeleteSite(corpName, siteName string) error {
	_, err := sc.doRequest("DELETE", fmt.Sprintf("/v0/corps/%s/sites/%s", corpName, siteName), "")
	if err != nil {
		return err
	}
	return nil
}

// Condition contains rule condition
type Condition struct {
	Type          string      `json:"type,omitempty"`          //(group, single)
	GroupOperator string      `json:"groupOperator,omitempty"` // type: group - Conditions that must be matched when evaluating the request (all, any)
	Field         string      `json:"field,omitempty"`         // type: single - (scheme, method, path, useragent, domain, ip, responseCode, agentname, paramname, paramvalue, country, name, valueString, valueInt, valueIp, signalType)
	Operator      string      `json:"operator,omitempty"`      // type: single - (equals, doesNotEqual, contains, doesNotContain, greaterEqual, lesserEqual, like, notLike, exists, doesNotExist, inList, notInList)
	Value         string      `json:"value,omitempty"`         // type: single - See request fields (https://docs.signalsciences.net/using-signal-sciences/features/rules/#request-fields)
	Conditions    []Condition `json:"conditions,omitempty"`
}

// Action contains the rule action
type Action struct {
	Type             string `json:"type,omitempty"` //(block, allow, exclude, browserChallenge)
	Signal           string `json:"signal,omitempty"`
	ResponseCode     int    `json:"responseCode,omitempty"`     //(400-499)
	RedirectURL      string `json:"redirectURL,omitempty"`      // requires ResponseCode 301 or 302
	AllowInteractive bool   `json:"allowInteractive,omitempty"` // used with browserChallenge
}

// ClientIdentifier contains the client identifier fields for site rules of type rate_limit
type ClientIdentifier struct {
	Key  string `json:"key,omitempty"`
	Name string `json:"name,omitempty"`
	Type string `json:"type"`
}

// RateLimit holds all the data that is specific to rate limit rules
type RateLimit struct {
	Threshold         int                `json:"threshold"`
	Interval          int                `json:"interval"` // interval in minutes, 1 or 10
	Duration          int                `json:"duration"` // duration in seconds
	ClientIdentifiers []ClientIdentifier `json:"clientIdentifiers"`
}

// CreateSiteRuleBody contains the rule for the site
type CreateSiteRuleBody struct {
	Type           string      `json:"type,omitempty"`          //(signal, request, rateLimit)
	GroupOperator  string      `json:"groupOperator,omitempty"` // type: group - Conditions that must be matched when evaluating the request (all, any)
	Enabled        bool        `json:"enabled,omitempty"`
	Reason         string      `json:"reason,omitempty"`     // Description of the rule
	Signal         string      `json:"signal,omitempty"`     // The signal id of the signal being excluded. Null unless type==request
	Expiration     string      `json:"expiration,omitempty"` // Date the rule will automatically be disabled. If rule is always enabled, will return empty string
	Conditions     []Condition `json:"conditions,omitempty"`
	Actions        []Action    `json:"actions,omitempty"`
	RateLimit      *RateLimit  `json:"rateLimit,omitempty"` // Null unless type==rateLimit
	RequestLogging string      `json:"requestlogging,omitempty"`
}

// ResponseSiteRuleBody contains the response from creating the rule
type ResponseSiteRuleBody struct {
	CreateSiteRuleBody
	ID        string    `json:"id"`        // internal ID
	CreatedBy string    `json:"createdby"` // Email address of the user that created the item
	Created   time.Time `json:"created"`   // Created RFC3339 date time
	Updated   time.Time `json:"updated"`   // Last updated RFC3339 date time
}

// ResponseSiteRuleBodyList contains the returned rules
type ResponseSiteRuleBodyList struct {
	TotalCount int                    `json:"totalCount"`
	Data       []ResponseSiteRuleBody `json:"data"`
}

// CreateSiteRule creates a rule and returns the response
func (sc *Client) CreateSiteRule(corpName, siteName string, body CreateSiteRuleBody) (ResponseSiteRuleBody, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return ResponseSiteRuleBody{}, err
	}
	resp, err := sc.doRequest("POST", fmt.Sprintf("/v0/corps/%s/sites/%s/rules", corpName, siteName), string(b))
	if err != nil {
		return ResponseSiteRuleBody{}, err
	}
	return getResponseSiteRuleBody(resp)
}

// UpdateSiteRuleByID updates a rule and returns a response
func (sc *Client) UpdateSiteRuleByID(corpName, siteName, id string, body CreateSiteRuleBody) (ResponseSiteRuleBody, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return ResponseSiteRuleBody{}, err
	}
	resp, err := sc.doRequest("PUT", fmt.Sprintf("/v0/corps/%s/sites/%s/rules/%s", corpName, siteName, id), string(b))
	if err != nil {
		return ResponseSiteRuleBody{}, err
	}
	return getResponseSiteRuleBody(resp)
}

// DeleteSiteRuleByID deletes a rule and returns an error
func (sc *Client) DeleteSiteRuleByID(corpName, siteName, id string) error {
	_, err := sc.doRequest("DELETE", fmt.Sprintf("/v0/corps/%s/sites/%s/rules/%s", corpName, siteName, id), "")
	if err != nil {
		return err
	}
	return nil
}

// GetSiteRuleByID get a site rule by id
func (sc *Client) GetSiteRuleByID(corpName, siteName, id string) (ResponseSiteRuleBody, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites/%s/rules/%s", corpName, siteName, id), "")
	if err != nil {
		return ResponseSiteRuleBody{}, err
	}
	return getResponseSiteRuleBody(resp)
}

func getResponseSiteRuleBody(response []byte) (ResponseSiteRuleBody, error) {
	var responseSiteRules ResponseSiteRuleBody
	err := json.Unmarshal(response, &responseSiteRules)
	if err != nil {
		return ResponseSiteRuleBody{}, err
	}
	return responseSiteRules, nil
}

// GetAllSiteRules Lists the Site Rules
func (sc *Client) GetAllSiteRules(corpName, siteName string) (ResponseSiteRuleBodyList, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites/%s/rules", corpName, siteName), "")
	if err != nil {
		return ResponseSiteRuleBodyList{}, err
	}

	var responseRulesList ResponseSiteRuleBodyList
	err = json.Unmarshal(resp, &responseRulesList)
	if err != nil {
		return ResponseSiteRuleBodyList{}, err
	}

	return responseRulesList, nil
}

// CreateListBody Create List Request
type CreateListBody struct {
	Name        string   `json:"name,omitempty"`        // Descriptive list name
	Type        string   `json:"type,omitempty"`        // List types (string, ip, country, wildcard, signal)
	Description string   `json:"description,omitempty"` // Optional list description
	Entries     []string `json:"entries,omitempty"`     // List entries
}

// UpdateListBody update list
type UpdateListBody struct {
	Description string  `json:"description,omitempty"` // Optional list description
	Entries     Entries `json:"entries,omitempty"`     // List entries
}

// Entries List entries
type Entries struct {
	Additions []string `json:"additions,omitempty"` // List additions
	Deletions []string `json:"deletions,omitempty"` // List deletions
}

// ResponseListBody contains the response from creating the list
type ResponseListBody struct {
	CreateListBody
	ID        string    `json:"id"`        // internal ID
	CreatedBy string    `json:"createdby"` // Email address of the user that created the item
	Created   time.Time `json:"created"`   // Created RFC3339 date time
	Updated   time.Time `json:"updated"`   // Last updated RFC3339 date time
}

// ResponseListBodyList contains the returned list
type ResponseListBodyList struct {
	// TotalCount int                `json:"totalCount"`
	Data []ResponseListBody `json:"data"` // Site List data
}

// CreateSiteList Create a site list
func (sc *Client) CreateSiteList(corpName, siteName string, body CreateListBody) (ResponseListBody, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return ResponseListBody{}, err
	}
	resp, err := sc.doRequest("POST", fmt.Sprintf("/v0/corps/%s/sites/%s/lists", corpName, siteName), string(b))
	if err != nil {
		return ResponseListBody{}, err
	}
	return getResponseListBody(resp)
}

func getResponseListBody(response []byte) (ResponseListBody, error) {
	var responseBody ResponseListBody
	err := json.Unmarshal(response, &responseBody)
	if err != nil {
		return ResponseListBody{}, err
	}
	return responseBody, nil
}

// UpdateSiteListByID updates a site list and returns a response
func (sc *Client) UpdateSiteListByID(corpName, siteName string, id string, body UpdateListBody) (ResponseListBody, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return ResponseListBody{}, err
	}
	resp, err := sc.doRequest("PATCH", fmt.Sprintf("/v0/corps/%s/sites/%s/lists/%s", corpName, siteName, id), string(b))
	if err != nil {
		return ResponseListBody{}, err
	}
	return getResponseListBody(resp)
}

// DeleteSiteListByID deletes a rule and returns an error
func (sc *Client) DeleteSiteListByID(corpName, siteName string, id string) error {
	_, err := sc.doRequest("DELETE", fmt.Sprintf("/v0/corps/%s/sites/%s/lists/%s", corpName, siteName, id), "")
	if err != nil {
		return err
	}
	return nil
}

// GetSiteListByID get site list by ID
func (sc *Client) GetSiteListByID(corpName, siteName string, id string) (ResponseListBody, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites/%s/lists/%s", corpName, siteName, id), "")
	if err != nil {
		return ResponseListBody{}, err
	}
	return getResponseListBody(resp)
}

// GetAllSiteLists get all site lists
func (sc *Client) GetAllSiteLists(corpName, siteName string) (ResponseListBodyList, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites/%s/lists", corpName, siteName), "")
	if err != nil {
		return ResponseListBodyList{}, err
	}
	var responseListBodyList ResponseListBodyList
	err = json.Unmarshal(resp, &responseListBodyList)
	if err != nil {
		return ResponseListBodyList{}, err
	}
	return responseListBodyList, nil
}

// CreateSiteRedactionBody Create redaction Request
type CreateSiteRedactionBody struct {
	Field         string `json:"field,omitempty"` // Field name
	RedactionType int    `json:"redactionType"`   // Type of redaction (0: Request Parameter, 1: Request Header, 2: Response Header)
}

// UpdateSiteRedactionBody update site redaction
// type UpdateSiteRedactionBody CreateSiteRedactionBody

// ResponseSiteRedactionBody redaction response
type ResponseSiteRedactionBody struct {
	CreateSiteRedactionBody
	ID        string    `json:"id"`        // internal ID
	CreatedBy string    `json:"createdby"` // Email address of the user that created the item
	Created   time.Time `json:"created"`   // Created RFC3339 date time
	Updated   time.Time `json:"updated"`   // Last updated RFC3339 date time
}

// ResponseSiteRedactionBodyList redaction response list
type ResponseSiteRedactionBodyList struct {
	// TotalCount int                    `json:"totalCount"`
	Data []ResponseSiteRedactionBody `json:"data"` // Site Redaction data
}

// CreateSiteRedaction Create a site list
func (sc *Client) CreateSiteRedaction(corpName, siteName string, body CreateSiteRedactionBody) (ResponseSiteRedactionBody, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return ResponseSiteRedactionBody{}, err
	}
	resp, err := sc.doRequest("POST", fmt.Sprintf("/v0/corps/%s/sites/%s/redactions", corpName, siteName), string(b))
	if err != nil {
		return ResponseSiteRedactionBody{}, err
	}
	redactionsData, err := getResponseSiteRedactionListBody(resp)

	return redactionsData.Data[len(redactionsData.Data)-1], err
}

func getResponseSiteRedactionListBody(response []byte) (ResponseSiteRedactionBodyList, error) {
	var responseBody ResponseSiteRedactionBodyList
	err := json.Unmarshal(response, &responseBody)
	if err != nil {
		return ResponseSiteRedactionBodyList{}, err
	}
	return responseBody, nil
}

func getResponseSiteRedactionBody(response []byte) (ResponseSiteRedactionBody, error) {
	var responseBody ResponseSiteRedactionBody
	err := json.Unmarshal(response, &responseBody)
	if err != nil {
		return ResponseSiteRedactionBody{}, err
	}
	return responseBody, nil
}

// GetSiteRedactionByID get a site redaction by id
func (sc *Client) GetSiteRedactionByID(corpName, siteName, id string) (ResponseSiteRedactionBody, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites/%s/redactions/%s", corpName, siteName, id), "")
	if err != nil {
		return ResponseSiteRedactionBody{}, err
	}
	return getResponseSiteRedactionBody(resp)
}

// UpdateSiteRedactionByID updates a site redaction and returns a response
func (sc *Client) UpdateSiteRedactionByID(corpName, siteName string, id string, body CreateSiteRedactionBody) (ResponseSiteRedactionBody, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return ResponseSiteRedactionBody{}, err
	}
	resp, err := sc.doRequest("PATCH", fmt.Sprintf("/v0/corps/%s/sites/%s/redactions/%s", corpName, siteName, id), string(b))
	if err != nil {
		return ResponseSiteRedactionBody{}, err
	}
	return getResponseSiteRedactionBody(resp)
}

// DeleteSiteRedactionByID deletes a redaction and returns an error
func (sc *Client) DeleteSiteRedactionByID(corpName, siteName string, id string) error {
	_, err := sc.doRequest("DELETE", fmt.Sprintf("/v0/corps/%s/sites/%s/redactions/%s", corpName, siteName, id), "")
	if err != nil {
		return err
	}
	return nil
}

// GetAllSiteRedactions Lists the Sites Redactions
func (sc *Client) GetAllSiteRedactions(corpName, siteName string) (ResponseSiteRedactionBodyList, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites/%s/redactions", corpName, siteName), "")
	if err != nil {
		return ResponseSiteRedactionBodyList{}, err
	}

	var responseRulesList ResponseSiteRuleBodyList
	err = json.Unmarshal(resp, &responseRulesList)
	if err != nil {
		return ResponseSiteRedactionBodyList{}, err
	}

	return getResponseSiteRedactionListBody(resp)
}

// CreateCorpRuleBody contains the rule of a Corp
type CreateCorpRuleBody struct {
	SiteNames      []string    `json:"siteNames,omitempty"` // Sites with the rule available. Rules with a global corpScope will return '[]'.
	Type           string      `json:"type,omitempty"`      //(request, signal)
	CorpScope      string      `json:"corpScope,omitempty"` // Whether the rule is applied to all sites or to specific sites. (global, specificSites)
	Enabled        bool        `json:"enabled,omitempty"`
	GroupOperator  string      `json:"groupOperator,omitempty"` // type: group - Conditions that must be matched when evaluating the request (all, any)
	Signal         string      `json:"signal,omitempty"`        // The signal id of the signal being excluded
	Reason         string      `json:"reason,omitempty"`        // Description of the rule
	Expiration     string      `json:"expiration,omitempty"`    // Date the rule will automatically be disabled. If rule is always enabled, will return empty string
	Conditions     []Condition `json:"conditions,omitempty"`
	Actions        []Action    `json:"actions,omitempty"`
	RequestLogging string      `json:"requestlogging,omitempty"`
}

// ResponseCorpRuleBody contains the response from creating the rule
type ResponseCorpRuleBody struct {
	CreateCorpRuleBody
	ID        string    `json:"id"`
	CreatedBy string    `json:"createdby"` // Email address of the user that created the item
	Created   time.Time `json:"created"`   // Created RFC3339 date time
	Updated   time.Time `json:"updated"`   // Last updated RFC3339 date time
}

// ResponseCorpRuleBodyList list
type ResponseCorpRuleBodyList struct {
	TotalCount int                    `json:"totalCount"`
	Data       []ResponseCorpRuleBody `json:"data"` // ResponseCorpRuleBody
}

// CreateCorpRule creates a rule and returns the response
func (sc *Client) CreateCorpRule(corpName string, body CreateCorpRuleBody) (ResponseCorpRuleBody, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return ResponseCorpRuleBody{}, err
	}
	resp, err := sc.doRequest("POST", fmt.Sprintf("/v0/corps/%s/rules", corpName), string(b))
	if err != nil {
		return ResponseCorpRuleBody{}, err
	}
	return getResponseCorpRuleBody(resp)
}

// GetCorpRuleByID get a site rule by id
func (sc *Client) GetCorpRuleByID(corpName, id string) (ResponseCorpRuleBody, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/rules/%s", corpName, id), "")
	if err != nil {
		return ResponseCorpRuleBody{}, err
	}
	return getResponseCorpRuleBody(resp)
}

// GetAllCorpRules get all corp rules
func (sc *Client) GetAllCorpRules(corpName string) (ResponseCorpRuleBodyList, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/rules", corpName), "")
	if err != nil {
		return ResponseCorpRuleBodyList{}, err
	}
	var responseRuleBodyList ResponseCorpRuleBodyList
	err = json.Unmarshal(resp, &responseRuleBodyList)
	if err != nil {
		return ResponseCorpRuleBodyList{}, err
	}
	return responseRuleBodyList, nil
}

// UpdateCorpRuleByID updates a rule and returns a response
func (sc *Client) UpdateCorpRuleByID(corpName, id string, body CreateCorpRuleBody) (ResponseCorpRuleBody, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return ResponseCorpRuleBody{}, err
	}
	resp, err := sc.doRequest("PUT", fmt.Sprintf("/v0/corps/%s/rules/%s", corpName, id), string(b))
	if err != nil {
		return ResponseCorpRuleBody{}, err
	}
	return getResponseCorpRuleBody(resp)
}

// DeleteCorpRuleByID deletes a rule and returns an error
func (sc *Client) DeleteCorpRuleByID(corpName, id string) error {
	_, err := sc.doRequest("DELETE", fmt.Sprintf("/v0/corps/%s/rules/%s", corpName, id), "")
	if err != nil {
		return err
	}
	return nil
}

func getResponseCorpRuleBody(response []byte) (ResponseCorpRuleBody, error) {
	var responseCorpRule ResponseCorpRuleBody
	err := json.Unmarshal(response, &responseCorpRule)
	if err != nil {
		return ResponseCorpRuleBody{}, err
	}
	return responseCorpRule, nil
}

// CreateCorpList corp list
func (sc *Client) CreateCorpList(corpName string, body CreateListBody) (ResponseListBody, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return ResponseListBody{}, err
	}
	resp, err := sc.doRequest("POST", fmt.Sprintf("/v0/corps/%s/lists", corpName), string(b))
	if err != nil {
		return ResponseListBody{}, err
	}
	return getResponseListBody(resp)
}

// GetCorpListByID get corp list by ID
func (sc *Client) GetCorpListByID(corpName string, id string) (ResponseListBody, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/lists/%s", corpName, id), "")
	if err != nil {
		return ResponseListBody{}, err
	}
	return getResponseListBody(resp)
}

// GetAllCorpLists get all corp lists
func (sc *Client) GetAllCorpLists(corpName string) (ResponseListBodyList, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/lists", corpName), "")
	if err != nil {
		return ResponseListBodyList{}, err
	}
	var responseListBodyList ResponseListBodyList
	err = json.Unmarshal(resp, &responseListBodyList)
	if err != nil {
		return ResponseListBodyList{}, err
	}
	return responseListBodyList, nil
}

// UpdateCorpListByID updates a corp list
func (sc *Client) UpdateCorpListByID(corpName string, id string, body UpdateListBody) (ResponseListBody, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return ResponseListBody{}, err
	}
	resp, err := sc.doRequest("PATCH", fmt.Sprintf("/v0/corps/%s/lists/%s", corpName, id), string(b))
	if err != nil {
		return ResponseListBody{}, err
	}
	return getResponseListBody(resp)
}

// DeleteCorpListByID deletes a rule and returns an error
func (sc *Client) DeleteCorpListByID(corpName string, id string) error {
	_, err := sc.doRequest("DELETE", fmt.Sprintf("/v0/corps/%s/lists/%s", corpName, id), "")
	if err != nil {
		return err
	}
	return nil
}

// CreateSignalTagBody create a signal tag
type CreateSignalTagBody struct {
	ShortName   string `json:"shortName,omitempty"`   // The display name of the signal tag
	Description string `json:"description,omitempty"` // Optional signal tag description
}

// UpdateSignalTagBody update a signal tag
type UpdateSignalTagBody struct {
	Description string `json:"description,omitempty"` // Optional signal tag description
}

// ResponseSignalTagBody response singnal tag
type ResponseSignalTagBody struct {
	CreateSignalTagBody
	TagName       string    `json:"tagName,omitempty"`  // The identifier for the signal tag
	LongName      string    `json:"longName,omitempty"` // The display name of the signal tag - deprecated
	Configurable  bool      `json:"configurable,omitempty"`
	Informational bool      `json:"informational,omitempty"`
	NeedsResponse bool      `json:"needsResponse,omitempty"`
	CreatedBy     string    `json:"createdBy,omitempty"` // Email address of the user that created the resource
	Created       time.Time `json:"created,omitempty"`   // Created RFC3339 date time
}

// ResponseSignalTagBodyList response list
type ResponseSignalTagBodyList struct {
	Data []ResponseSignalTagBody `json:"data"` // ResponseSignalTagBody
}

// CreateCorpSignalTag create signal tag
func (sc *Client) CreateCorpSignalTag(corpName string, body CreateSignalTagBody) (ResponseSignalTagBody, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return ResponseSignalTagBody{}, err
	}
	resp, err := sc.doRequest("POST", fmt.Sprintf("/v0/corps/%s/tags", corpName), string(b))
	if err != nil {
		return ResponseSignalTagBody{}, err
	}
	return getResponseSignalTagBody(resp)
}

// GetCorpSignalTagByID get corp signal by id
func (sc *Client) GetCorpSignalTagByID(corpName string, id string) (ResponseSignalTagBody, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/tags/%s", corpName, id), "")
	if err != nil {
		return ResponseSignalTagBody{}, err
	}
	return getResponseSignalTagBody(resp)
}

// GetAllCorpSignalTags get all corp signals
func (sc *Client) GetAllCorpSignalTags(corpName string) (ResponseSignalTagBodyList, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/tags", corpName), "")
	if err != nil {
		return ResponseSignalTagBodyList{}, err
	}
	var responseSignalTagBodyList ResponseSignalTagBodyList
	err = json.Unmarshal(resp, &responseSignalTagBodyList)
	if err != nil {
		return ResponseSignalTagBodyList{}, err
	}
	return responseSignalTagBodyList, nil
}

// UpdateCorpSignalTagByID update corp signal
func (sc *Client) UpdateCorpSignalTagByID(corpName string, id string, body UpdateSignalTagBody) (ResponseSignalTagBody, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return ResponseSignalTagBody{}, err
	}
	resp, err := sc.doRequest("PATCH", fmt.Sprintf("/v0/corps/%s/tags/%s", corpName, id), string(b))
	if err != nil {
		return ResponseSignalTagBody{}, err
	}
	return getResponseSignalTagBody(resp)
}

// DeleteCorpSignalTagByID delete signal tag by id
func (sc *Client) DeleteCorpSignalTagByID(corpName string, id string) error {
	_, err := sc.doRequest("DELETE", fmt.Sprintf("/v0/corps/%s/tags/%s", corpName, id), "")
	if err != nil {
		return err
	}
	return nil
}

func getResponseSignalTagBody(response []byte) (ResponseSignalTagBody, error) {
	var responseBody ResponseSignalTagBody
	err := json.Unmarshal(response, &responseBody)
	if err != nil {
		return ResponseSignalTagBody{}, err
	}
	return responseBody, nil
}

// CreateSiteSignalTag create signal tag
func (sc *Client) CreateSiteSignalTag(corpName, siteName string, body CreateSignalTagBody) (ResponseSignalTagBody, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return ResponseSignalTagBody{}, err
	}
	resp, err := sc.doRequest("POST", fmt.Sprintf("/v0/corps/%s/sites/%s/tags", corpName, siteName), string(b))
	if err != nil {
		return ResponseSignalTagBody{}, err
	}
	return getResponseSignalTagBody(resp)
}

// GetSiteSignalTagByID get site signal by id
func (sc *Client) GetSiteSignalTagByID(corpName, siteName, id string) (ResponseSignalTagBody, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites/%s/tags/%s", corpName, siteName, id), "")
	if err != nil {
		return ResponseSignalTagBody{}, err
	}
	return getResponseSignalTagBody(resp)
}

// GetAllSiteSignalTags get all site signals
func (sc *Client) GetAllSiteSignalTags(corpName, siteName string) (ResponseSignalTagBodyList, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites/%s/tags", corpName, siteName), "")
	if err != nil {
		return ResponseSignalTagBodyList{}, err
	}
	var responseSignalTagBodyList ResponseSignalTagBodyList
	err = json.Unmarshal(resp, &responseSignalTagBodyList)
	if err != nil {
		return ResponseSignalTagBodyList{}, err
	}
	return responseSignalTagBodyList, nil
}

// UpdateSiteSignalTagByID update site signal
func (sc *Client) UpdateSiteSignalTagByID(corpName, siteName, id string, body UpdateSignalTagBody) (ResponseSignalTagBody, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return ResponseSignalTagBody{}, err
	}
	resp, err := sc.doRequest("PATCH", fmt.Sprintf("/v0/corps/%s/sites/%s/tags/%s", corpName, siteName, id), string(b))
	if err != nil {
		return ResponseSignalTagBody{}, err
	}
	return getResponseSignalTagBody(resp)
}

// DeleteSiteSignalTagByID delete signal tag by id
func (sc *Client) DeleteSiteSignalTagByID(corpName, siteName, id string) error {
	_, err := sc.doRequest("DELETE", fmt.Sprintf("/v0/corps/%s/sites/%s/tags/%s", corpName, siteName, id), "")
	if err != nil {
		return err
	}
	return nil
}

// ConfiguredDetectionField configuration for detection field in UpdateDetectionBody
type ConfiguredDetectionField struct {
	Name  string      `json:"name,omitempty"`
	Value interface{} `json:"value"`
}

// DetectionUpdateBody body to update a detection
type DetectionUpdateBody struct {
	ID      string                     `json:"id,omitempty"`
	Name    string                     `json:"name"` // name of template
	Enabled bool                       `json:"enabled"`
	Fields  []ConfiguredDetectionField `json:"fields"`
}

// AlertUpdateBody body needed to update an alert
type AlertUpdateBody struct {
	LongName             string `json:"longName"`
	Interval             int    `json:"interval"`  // 1, 10 or 60
	Threshold            int    `json:"threshold"` // greater than 0, max 10000
	SkipNotifications    bool   `json:"skipNotifications,omitempty"`
	Enabled              bool   `json:"enabled"`
	Action               string `json:"action"`
	BlockDurationSeconds int    `json:"blockDurationSeconds,omitempty"`
}

// SiteTemplateRuleBody needed to update a site template rule
type SiteTemplateRuleBody struct {
	DetectionAdds    []Detection `json:"detectionAdds"`
	DetectionUpdates []Detection `json:"detectionUpdates"`
	DetectionDeletes []Detection `json:"detectionDeletes"`

	AlertAdds    []Alert `json:"alertAdds"`
	AlertUpdates []Alert `json:"alertUpdates"`
	AlertDeletes []Alert `json:"alertDeletes"`
}

// Detection basic struct for Detection
type Detection struct {
	DetectionUpdateBody
	Created   *time.Time `json:"created,omitempty"`
	CreatedBy string     `json:"created_by,omitempty"`
}

// Alert basic struct for an Alert
type Alert struct {
	AlertUpdateBody
	ID        string     `json:"id,omitempty"`
	Type      string     `json:"type,omitempty"`
	TagName   string     `json:"tag_name,omitempty"`
	FieldName string     `json:"field_name,omitempty"`
	Created   *time.Time `json:"created,omitempty"`
	CreatedBy string     `json:"created_by,omitempty"`
}

// SiteTemplate basic struct for a site template
type SiteTemplate struct {
	Name       string      `json:"name,omitempty"`
	Detections []Detection `json:"detections"`
	Alerts     []Alert     `json:"alerts"`
}

func getResponseSiteTemplateBody(response []byte) (SiteTemplate, error) {
	var responseBody SiteTemplate
	err := json.Unmarshal(response, &responseBody)
	if err != nil {
		return SiteTemplate{}, err
	}
	return responseBody, nil
}

// UpdateSiteTemplateRuleByID updates a site template rule
func (sc *Client) UpdateSiteTemplateRuleByID(corpName, siteName, id string, body SiteTemplateRuleBody) (SiteTemplate, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return SiteTemplate{}, err
	}
	resp, err := sc.doRequest("POST", fmt.Sprintf("/v0/corps/%s/sites/%s/configuredtemplates/%s", corpName, siteName, id), string(b))
	if err != nil {
		return SiteTemplate{}, err
	}
	return getResponseSiteTemplateBody(resp)
}

// GetSiteTemplateRuleByID retrieves a site template rule
func (sc *Client) GetSiteTemplateRuleByID(corpName, siteName, id string) (SiteTemplate, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites/%s/configuredtemplates/%s", corpName, siteName, id), "")
	if err != nil {
		return SiteTemplate{}, err
	}
	return getResponseSiteTemplateBody(resp)
}

// PrimaryAgentKey contains the secret and access keys used by the agents
type PrimaryAgentKey struct {
	Name      string
	AccessKey string
	SecretKey string
}

// GetSitePrimaryAgentKey retrieve the primary agent keys
func (sc *Client) GetSitePrimaryAgentKey(corpName, siteName string) (PrimaryAgentKey, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites/%s/keys", corpName, siteName), "")
	if err != nil {
		return PrimaryAgentKey{}, err
	}
	var primaryKey PrimaryAgentKey
	if err = json.Unmarshal(resp, &primaryKey); err != nil {
		return PrimaryAgentKey{}, err
	}

	return primaryKey, nil
}

func (sc *Client) doRequestDetailed(method, url, reqBody string) (*http.Response, error) {
	client := &http.Client{}

	var b io.Reader
	if reqBody != "" {
		b = strings.NewReader(reqBody)
	}

	req, _ := http.NewRequest(method, apiURL+url, b)

	if sc.email != "" {
		// token auth
		req.Header.Set("X-API-User", sc.email)
		req.Header.Set("X-API-Token", sc.token)
	} else {
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", sc.token))
	}

	if sc.fastlyKey != "" {
		req.Header.Set("Fastly-Key", sc.fastlyKey)
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Set("User-Agent", "go-sigsci")

	resp, err := client.Do(req)

	return resp, err
}

// FastlyService contains details about a Fastly Service mapped a site.
type FastlyService struct {
	ID        string    `json:"id"`
	AccountID string    `json:"accountID"`
	Created   time.Time `json:"created"`
	CreatedBy string    `json:"createdBy"`
}

// EdgeDeployment contains details about an Edge Deployment
type EdgeDeployment struct {
	AgentHostName    string          `json:"AgentHostName"`
	ServicesAttached []FastlyService `json:"ServicesAttached"`
}

// GetEdgeDeployment retrieves currently deployed EdgeWafs and Fastly Services mapped to a site..
func (sc *Client) GetEdgeDeployment(corpName, siteName string) (EdgeDeployment, error) {
	resp, err := sc.doRequest("GET", fmt.Sprintf("/v0/corps/%s/sites/%s/edgeDeployment", corpName, siteName), "")
	if err != nil {
		return EdgeDeployment{}, err
	}

	var edgeDeployment EdgeDeployment
	err = json.Unmarshal(resp, &edgeDeployment)
	if err != nil {
		return EdgeDeployment{}, err
	}

	return edgeDeployment, nil
}

// CreateOrUpdateEdgeDeployment initializes the Next-Gen WAF deployment in Compute@Edge and configures the site for Edge Deployment.
func (sc *Client) CreateOrUpdateEdgeDeployment(corpName, siteName string, authorizedServices []string) error {
	payload := make(map[string]interface{})
	if len(authorizedServices) > 0 {
		payload["authorizedServices"] = authorizedServices
	}
	// Convert payload to JSON if it contains data
	var b []byte
	var err error
	if len(payload) > 0 {
		b, err = json.Marshal(payload)
		if err != nil {
			return err
		}
	}
	_, err = sc.doRequest("PUT", fmt.Sprintf("/v0/corps/%s/sites/%s/edgeDeployment", corpName, siteName), string(b))
	if err != nil {
		return err
	}
	return err
}

// DeleteEdgeDeployment deletes an edge deployment
func (sc *Client) DeleteEdgeDeployment(corpName, siteName string) error {
	_, err := sc.doRequest("DELETE", fmt.Sprintf("/v0/corps/%s/sites/%s/edgeDeployment", corpName, siteName), "")

	return err
}

type CreateOrUpdateEdgeDeploymentServiceBody struct {
	ActivateVersion *bool `json:"activateVersion,omitempty"` // Activate Fastly VCL service after clone
	PercentEnabled  *int  `json:"percentEnabled,omitempty"`  // Percentage of traffic to send to NGWAF@Edge
	CustomClientIP  *bool `json:"customClientIP,omitempty"`  // enable to prevent Fastly-Client-IP from being overwritten by the NGWAF@Edge
}

// CreateOrUpdateEdgeDeploymentService copies the backends from the Fastly service to the
// Edge Deployment and pre-configures the Fastly service with an edge dictionary and custom VCL.
func (sc *Client) CreateOrUpdateEdgeDeploymentService(corpName, siteName, fastlySID string, body CreateOrUpdateEdgeDeploymentServiceBody) error {
	if sc.fastlyKey == "" {
		return errors.New("please set Fastly-Key with the client.SetFastlyKey method")
	}

	b, err := json.Marshal(body)
	if err != nil {
		return err
	}

	// Call to link inspection service with the Fastly service will fail if inspection service is not available. Set sleeptime to
	// 20 seconds for the first sleep before retrying the first time
	sleepTime := 20 * time.Second

	for i := 0; i < 6; i++ {
		resp, err := sc.doRequestDetailed("PUT", fmt.Sprintf("/v0/corps/%s/sites/%s/edgeDeployment/%s", corpName, siteName, fastlySID), string(b))

		// Add case statements for the following
		// 400 means that there is some sort of incorrect user input. Need to output the body of the response as the error
		// 404 needs to retry because the NGWAF edge service is not ready yet.
		switch resp.StatusCode {
		case http.StatusOK: // 200
			return err
		case http.StatusBadRequest: // 400
			fallthrough
		case http.StatusUnauthorized: // 401
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			return errMsg(body) // Typically incorrect user info
		case http.StatusNotFound: // 404
			// Only sleep if Retry-After response header is available
			if resp.Header.Get("Retry-After") != "" {
				time.Sleep(sleepTime)
				// Add 5 seconds to sleeptime for every consecutive retry e.g. wait 20, 25, 30, 35, 40, 45 seconds
				sleepTime += 5 * time.Second
			} else {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return err
				}
				return errMsg(body) // 404 happened for some other reason
			}
		default: // Something else
			// Wait and send another request
			time.Sleep(sleepTime)
		}
	}

	// If we got here linking of Fastly Service with Inspection Service has timed out
	return errors.New("timed out associating fastly service with inspection service retry later")
}

// DetachEdgeDeploymentService removes all backends from the Edge Deployment connected to the Fastly service
// and detaches the Fastly Service from the Edge Deployment.
func (sc *Client) DetachEdgeDeploymentService(corpName, siteName, fastlySID string) error {
	if sc.fastlyKey == "" {
		return errors.New("please set Fastly-Key with the client.SetFastlyKey method")
	}

	_, err := sc.doRequest("DELETE", fmt.Sprintf("/v0/corps/%s/sites/%s/edgeDeployment/%s", corpName, siteName, fastlySID), "")

	return err
}

// UpdateEdgeDeploymentBackends checks if any changes were made to the Fastly service's backends
// and updates the Edge Deployment if necessary.
func (sc *Client) UpdateEdgeDeploymentBackends(corpName, siteName, fastlySID string) error {
	if sc.fastlyKey == "" {
		return errors.New("please set Fastly-Key with the client.SetFastlyKey method")
	}

	_, err := sc.doRequest("PUT", fmt.Sprintf("/v0/corps/%s/sites/%s/edgeDeployment/%s/backends", corpName, siteName, fastlySID), "")

	return err
}

// Simulation request the sample request and response for the simulation test
type SimulationBody struct {
	SampleRequest  string `json:"sample_request"`
	SampleResponse string `json:"sample_response"`
}

// SimulationResponse the response of the simulation test
type ResponseSimulationBody struct {
	Data struct {
		WafResponse  int `json:"waf_response"`
		ResponseCode int `json:"response_code"`
		ResponseSize int `json:"response_size"`
		Signals      []struct {
			Type      string `json:"type"`
			Location  string `json:"location"`
			Name      string `json:"name"`
			Value     string `json:"value"`
			Detector  string `json:"detector"`
			Redaction int    `json:"redaction"`
		} `json:"signals"`
	} `json:"data"`
}

// getResponseSimulationBody gets the simulation response
func getResponseSimulationBody(response []byte) (ResponseSimulationBody, error) {
	var responseSimulation ResponseSimulationBody
	err := json.Unmarshal(response, &responseSimulation)
	if err != nil {
		return ResponseSimulationBody{}, err
	}
	return responseSimulation, nil
}

// SendSimulation sends a simulation test and returns the response
func (sc *Client) SendSimulation(corpName, siteName string, body SimulationBody) (ResponseSimulationBody, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return ResponseSimulationBody{}, err
	}
	resp, err := sc.doRequest("POST", fmt.Sprintf("/v0/corps/%s/sites/%s/simulator", corpName, siteName), string(b))
	if err != nil {
		return ResponseSimulationBody{}, err
	}
	return getResponseSimulationBody(resp)
}
