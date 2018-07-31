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
		if resp.StatusCode != http.StatusOK {
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

// UpdateCorp updates a corp by name.
func (sc *Client) UpdateCorp(corpName string, query url.Values) (Corp, error) {
	if query.Encode() == "" {
		return Corp{}, errors.New("query parameters required")
	}

	url := fmt.Sprintf("/v0/corps/%s/sites/%s/events?%s", corpName, query.Encode())

	resp, err := sc.doRequest("PATCH", url, "")
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

// GetOverviewReport gets the overview report data for a given corp.

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

// UpdateSite updates a site by name.

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

// CreateCustomAlert creates a custom alert.

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

// GetCustomAlert gets a custom alert by ID.

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

// ExpireEvent expires an event by ID.

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

// SearchRequests searches requests.

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

// requestsResponse is the response for the search requests endpoint
type requestsResponse struct {
	TotalCount int
	Next       map[string]string
	Data       []Request
}

// GetRequestFeed gets the request feed for the site.

// ListIP is a whitelisted or blacklisted IP address.
type ListIP struct {
	ID        string
	Source    string
	Expires   time.Time
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

// AddToWhitelist adds an IP address to the whitelist.

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

// AddToBlacklist adds an IP address to the blacklist.

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

// AddRedaction adds a redaction.

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

// AddIntegrations adds an integration.

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

// UpdateIntegration updates an integration by ID.

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

// AddParam adds a whitelisted parameter.

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

// AddPath adds a whitelisted path.

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

// AddHeaderLink adds a header link.

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

// UpdateSiteMember updates a site member by email.

// DeleteSiteMember deletes a site member by email.
func (sc *Client) DeleteSiteMember(corpName, siteName, email string) error {
	_, err := sc.doRequest("DELETE", fmt.Sprintf("/v0/corps/%s/sites/%s/members/%s", corpName, siteName, email), "")

	return err
}

// InviteSiteMember invites a site member by email.

// GetSiteMonitor gets the site monitor URL.
// GenerateSiteMonitor generates a site monitor URL.
// EnableSiteMonitor enables the site monitor URL for a given site.
// DisableSiteMonitor disables the site monitor URL for a given site.

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

// GetTimeseries gets timeseries request info.

// GetHealthReport gets the health report for a given corp by name.
