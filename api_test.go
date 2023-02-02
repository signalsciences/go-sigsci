package sigsci

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

type TestCreds struct {
	email                string
	token                string
	corp                 string
	site                 string
	testCloudWAFInstance bool
}

var testcreds = TestCreds{
	email: os.Getenv("SIGSCI_EMAIL"),
	token: os.Getenv("SIGSCI_TOKEN"),
	corp:  os.Getenv("SIGSCI_CORP"),
	site:  os.Getenv("SIGSCI_SITE"),
}

func init() {
	// Cloud WAF Instance tests are run if `SIGSCI_TEST_CLOUDWAFINSTANCE` is set to any of the folloiwng:  1, t, T, TRUE, true, True.
	testCWAFInstance, err := strconv.ParseBool(os.Getenv("SIGSCI_TEST_CLOUDWAFINSTANCE"))
	if err == nil && testCWAFInstance {
		testcreds.testCloudWAFInstance = true
	}
}

func ExampleClient_InviteUser() {
	email := testcreds.email
	password := testcreds.token
	sc, err := NewClient(email, password)
	if err != nil {
		log.Fatal(err)
	}

	invite := NewCorpUserInvite(RoleCorpUser, []SiteMembership{
		NewSiteMembership(testcreds.site, RoleSiteOwner),
	})

	_, err = sc.InviteUser(testcreds.corp, "test@test.net", invite)
	if err != nil {
		log.Fatal(err)
	}
}

func TestGoUserTokenClient(t *testing.T) {
	testCases := []struct {
		name  string
		email string
		token string
	}{
		{
			name:  "working user pass creds",
			email: testcreds.email,
			token: testcreds.token,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			sc := NewTokenClient(testCase.email, testCase.token)
			if corps, err := sc.ListCorps(); err != nil {
				t.Fatal(err)
			} else {
				if testcreds.corp != corps[0].Name {
					t.Errorf("Corp ")
				}
			}
		})
	}
}
func TestCreateUpdateDeleteSite(t *testing.T) {
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := testcreds.corp

	siteBody := CreateSiteBody{
		Name:                 "test-site",
		DisplayName:          "Test Site",
		AgentLevel:           "block",
		BlockHTTPCode:        406,   // TODO test non-default value once api supports it
		BlockDurationSeconds: 86400, // TODO test non-default value once api supports it
		AgentAnonMode:        "",
	}
	siteresponse, err := sc.CreateSite(corp, siteBody)
	if err != nil {
		t.Fatal(err)
	}
	if siteresponse.DisplayName != "Test Site" {
		t.Errorf("Displayname got %s expected %s", siteresponse.DisplayName, "Test Site")
	}
	if siteresponse.AgentLevel != "block" {
		t.Errorf("AgentLevel got %s expected %s", siteresponse.AgentLevel, "block")
	}
	if siteresponse.BlockHTTPCode != 406 {
		t.Errorf("BlockHTTPCode got %d expected %d", siteresponse.BlockHTTPCode, 406)
	}
	if siteresponse.BlockDurationSeconds != 86400 {
		t.Errorf("BlockDurationSeconds got %d expected %d", siteresponse.BlockDurationSeconds, 86400)
	}
	if siteresponse.AgentAnonMode != "" {
		t.Errorf("AgentAnonMode got %s expected %s", siteresponse.AgentAnonMode, "")
	}

	updateSite, err := sc.UpdateSite(corp, siteBody.Name, UpdateSiteBody{
		DisplayName:          "Test Site 2",
		AgentLevel:           "off",
		BlockDurationSeconds: 86402,
		BlockHTTPCode:        406, // TODO increment this value once api supports it
		AgentAnonMode:        "EU",
	})

	if err != nil {
		t.Fatal(err)
	}

	if updateSite.DisplayName != "Test Site 2" {
		t.Errorf("Displayname got %s expected %s", updateSite.DisplayName, "Test Site 2")
	}
	if updateSite.AgentLevel != "off" {
		t.Errorf("AgentLevel got %s expected %s", updateSite.AgentLevel, "off")
	}
	if updateSite.BlockHTTPCode != 406 {
		t.Errorf("BlockHTTPCode got %d expected %d", updateSite.BlockHTTPCode, 406)
	}
	if updateSite.BlockDurationSeconds != 86402 {
		t.Errorf("BlockDurationSeconds got %d expected %d", updateSite.BlockDurationSeconds, 86402)
	}
	if updateSite.AgentAnonMode != "EU" {
		t.Errorf("AgentAnonMode got %s expected %s", updateSite.AgentAnonMode, "EU")
	}

	err = sc.DeleteSite(corp, siteBody.Name)
	if err != nil {
		t.Errorf("%#v", err)
	}
}

func compareSiteRuleBody(sr1, sr2 CreateSiteRuleBody) bool {
	if sr1.Enabled != sr2.Enabled {
		return false
	}
	if sr1.Reason != sr2.Reason {
		return false
	}
	if sr1.Type != sr2.Type {
		return false
	}
	if sr1.Signal != sr2.Signal {
		return false
	}
	if sr1.Expiration != sr2.Expiration {
		return false
	}
	if sr1.GroupOperator != sr2.GroupOperator {
		return false
	}
	if sr1.RequestLogging != sr2.RequestLogging {
		return false
	}
	return true
}

func TestCreateReadUpdateDeleteSiteRules(t *testing.T) {
	createSiteRulesBody := CreateSiteRuleBody{
		Type:          "signal",
		GroupOperator: "all",
		Enabled:       true,
		Reason:        "Example site rule",
		Signal:        "SQLI",
		Expiration:    "",
		Conditions: []Condition{
			{
				Type:     "single",
				Field:    "ip",
				Operator: "equals",
				Value:    "1.2.3.4",
			},
			{
				Type:          "group",
				GroupOperator: "any",
				Conditions: []Condition{
					{
						Type:     "single",
						Field:    "ip",
						Operator: "equals",
						Value:    "5.6.7.8",
					},
				},
			},
		},
		Actions: []Action{
			{
				Type: "excludeSignal",
			},
		},
	}
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := testcreds.corp
	site := testcreds.site
	createResp, err := sc.CreateSiteRule(corp, site, createSiteRulesBody)
	if err != nil {
		t.Fatal(err)
	}
	if !compareSiteRuleBody(createSiteRulesBody, createResp.CreateSiteRuleBody) {
		t.Errorf("CreateSiteRulesgot: %v expected %v", createResp, createSiteRulesBody)
	}

	readResp, err := sc.GetSiteRuleByID(corp, site, createResp.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !compareSiteRuleBody(createSiteRulesBody, readResp.CreateSiteRuleBody) {
		t.Errorf("CreateSiteRulesgot: %v expected %v", createResp, createSiteRulesBody)
	}
	updateSiteRuleBody := CreateSiteRuleBody{
		Type:          "signal",
		GroupOperator: "all",
		Enabled:       true,
		Reason:        "Example site rule",
		Signal:        "SQLI",
		Expiration:    "",
		Conditions: []Condition{
			{
				Type:     "single",
				Field:    "ip",
				Operator: "equals",
				Value:    "1.2.3.4",
			},
			{
				Type:          "group",
				GroupOperator: "any",
				Conditions: []Condition{
					{
						Type:     "single",
						Field:    "ip",
						Operator: "equals",
						Value:    "9.10.11.12",
					},
				},
			},
		},
		Actions: []Action{
			{
				Type: "excludeSignal",
			},
		},
	}
	updateResp, err := sc.UpdateSiteRuleByID(corp, site, createResp.ID, updateSiteRuleBody)
	if err != nil {
		t.Fatal(err)
	}
	if !compareSiteRuleBody(updateSiteRuleBody, updateResp.CreateSiteRuleBody) {
		t.Errorf("CreateSiteRules got: %v expected %v", updateResp, updateSiteRuleBody)
	}

	readall, err := sc.GetAllSiteRules(corp, site)
	if err != nil {
		t.Fatal(err)
	}
	if len(readall.Data) != 1 {
		t.Error()
	}
	if readall.TotalCount != 1 {
		t.Error()
	}

	if !compareSiteRuleBody(updateSiteRuleBody, readall.Data[0].CreateSiteRuleBody) {
		t.Errorf("CreateSiteRules update site rule body = %v, want %v", updateSiteRuleBody, readall.Data)
	}

	err = sc.DeleteSiteRuleByID(corp, site, createResp.ID)
	if err != nil {
		t.Fatal(err)
	}
}

func TestUnMarshalListData(t *testing.T) {
	resp := []byte(fmt.Sprintf(`{
		"totalCount": 1,
		"data": [
		  {
			"id": "5e84ec28bf612801c7f0f109",
			"siteNames": [
			  "%s"
			],
			"type": "signal",
			"enabled": true,
			"groupOperator": "all",
			"conditions": [
			  {
				"type": "single",
				"field": "ip",
				"operator": "equals",
				"value": "1.2.3.4"
			  }
			],
			"actions": [
			  {
				"type": "excludeSignal"
			  }
			],
			"signal": "SQLI",
			"reason": "Example site rule",
			"expiration": "",
			"createdBy": "test@gmail.com",
			"created": "2020-04-01T19:31:52Z",
			"updated": "2020-04-01T19:31:52Z"
		  }
		]
	  }`, testcreds.site))

	var responseRulesList ResponseSiteRuleBodyList
	err := json.Unmarshal(resp, &responseRulesList)
	if err != nil {
		t.Fatal(err)
	}
	if responseRulesList.TotalCount != 1 {
		t.Error()
	}
	if len(responseRulesList.Data) != 1 {
		t.Error()
	}
	if responseRulesList.Data[0].ID != "5e84ec28bf612801c7f0f109" {
		t.Error()
	}
}

func TestDeleteAllSiteRules(t *testing.T) {
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := testcreds.corp
	site := testcreds.site
	respList, err := sc.GetAllSiteRules(corp, site)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range respList.Data {
		sc.DeleteSiteRuleByID(corp, site, rule.ID)
	}
	respList, err = sc.GetAllSiteRules(corp, site)
	if err != nil {
		t.Fatal(err)
	}
	if len(respList.Data) != 0 {
		t.Error()
	}
}

func TestCreateReadUpdateDeleteSiteList(t *testing.T) {
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := testcreds.corp
	site := testcreds.site
	createSiteListBody := CreateListBody{
		Name:        "My new list",
		Type:        "ip",
		Description: "Some IPs we are putting in a list",
		Entries: []string{
			"4.5.6.7",
			"2.3.4.5",
			"1.2.3.4",
		},
	}
	createresp, err := sc.CreateSiteList(corp, site, createSiteListBody)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(createSiteListBody, createresp.CreateListBody) {
		t.Error("Site list body not equal after create")
	}

	readresp, err := sc.GetSiteListByID(corp, site, createresp.ID)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(createSiteListBody, readresp.CreateListBody) {
		t.Error("Site list body not equal after read")
	}

	updateSiteListBody := UpdateListBody{
		Description: "Some IPs we are updating in the list",
		Entries: Entries{
			Additions: []string{"3.4.5.6"},
			Deletions: []string{"4.5.6.7"},
		},
	}
	updateresp, err := sc.UpdateSiteListByID(corp, site, readresp.ID, updateSiteListBody)
	if err != nil {
		t.Fatal(err)
	}

	updatedSiteListBody := CreateListBody{
		Name:        "My new list",
		Type:        "ip",
		Description: "Some IPs we are updating in the list",
		Entries: []string{
			"2.3.4.5",
			"1.2.3.4",
			"3.4.5.6",
		},
	}
	if !reflect.DeepEqual(updatedSiteListBody, updateresp.CreateListBody) {
		t.Error("Site list body not equal")
	}
	readall, err := sc.GetAllSiteLists(corp, site)
	if err != nil {
		t.Fatal(err)
	}

	if len(readall.Data) != 1 {
		t.Error()
	}
	if !reflect.DeepEqual(updatedSiteListBody, readall.Data[0].CreateListBody) {
		t.Error("Site list body not equal")
	}
	err = sc.DeleteSiteListByID(corp, site, readresp.ID)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCreateMultipleRedactions(t *testing.T) {
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := testcreds.corp
	site := testcreds.site

	createSiteRedactionBody := CreateSiteRedactionBody{
		Field:         "privatefield",
		RedactionType: 2,
	}
	createresp, err := sc.CreateSiteRedaction(corp, site, createSiteRedactionBody)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(createSiteRedactionBody, createresp.CreateSiteRedactionBody) {
		t.Error("Site redaction body not equal after create")
	}

	createSiteRedactionBody2 := CreateSiteRedactionBody{
		Field:         "cookie",
		RedactionType: 2,
	}
	createresp2, err := sc.CreateSiteRedaction(corp, site, createSiteRedactionBody2)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(createSiteRedactionBody2, createresp2.CreateSiteRedactionBody) {
		t.Error("Site redaction body not equal after create")
	}

	createSiteRedactionBody3 := CreateSiteRedactionBody{
		Field:         "cookie",
		RedactionType: 0,
	}
	createresp3, err := sc.CreateSiteRedaction(corp, site, createSiteRedactionBody3)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(createSiteRedactionBody3, createresp3.CreateSiteRedactionBody) {
		t.Error("Site redaction body not equal after create")
	}

	err = sc.DeleteSiteRedactionByID(corp, site, createresp.ID)
	if err != nil {
		t.Fatal(err)
	}
	err = sc.DeleteSiteRedactionByID(corp, site, createresp2.ID)
	if err != nil {
		t.Fatal(err)
	}
	err = sc.DeleteSiteRedactionByID(corp, site, createresp3.ID)
	if err != nil {
		t.Fatal(err)
	}
}
func TestCreateListUpdateDeleteRedaction(t *testing.T) {
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := testcreds.corp
	site := testcreds.site

	createSiteRedactionBody := CreateSiteRedactionBody{
		Field:         "privatefield",
		RedactionType: 2,
	}
	createresp, err := sc.CreateSiteRedaction(corp, site, createSiteRedactionBody)

	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(createSiteRedactionBody, createresp.CreateSiteRedactionBody) {
		t.Error("Site redaction body not equal after create")
	}

	readresp, err := sc.GetSiteRedactionByID(corp, site, createresp.ID)
	if !reflect.DeepEqual(createSiteRedactionBody, readresp.CreateSiteRedactionBody) {
		t.Error("Site redaction body not equal after read")
	}
	if err != nil {
		t.Fatal(err)
	}

	updateSiteRedactionBody := CreateSiteRedactionBody{
		Field:         "cookie",
		RedactionType: 0,
	}
	updatedresp, err := sc.UpdateSiteRedactionByID(corp, site, createresp.ID, updateSiteRedactionBody)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(updateSiteRedactionBody, updatedresp.CreateSiteRedactionBody) {
		t.Error("Site redaction body not equal after update")
	}
	readall, err := sc.GetAllSiteRedactions(corp, site)
	if err != nil {
		t.Fatal(err)
	}

	if len(readall.Data) != 1 {
		t.Error("incorrect number of site redactions, make sure you didnt add any manually")
	}
	if !reflect.DeepEqual(updateSiteRedactionBody, readall.Data[0].CreateSiteRedactionBody) {
		t.Error("Site redaction body not equal after update")
	}
	err = sc.DeleteSiteRedactionByID(corp, site, createresp.ID)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSiteCreateReadUpdateDeleteAlerts(t *testing.T) {
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := testcreds.corp
	site := testcreds.site

	createCustomAlert := CustomAlertBody{
		TagName:              "SQLI",
		LongName:             "Example Alert",
		Interval:             1,
		Threshold:            10,
		Enabled:              true,
		Action:               "flagged",
		BlockDurationSeconds: 3600,
	}
	createresp, err := sc.CreateCustomAlert(corp, site, createCustomAlert)
	if err != nil {
		t.Fatal(err)
	}
	// set unknown fields just for equality
	if createCustomAlert.TagName != createresp.TagName {
		t.Error("tag names not equal")
	}
	if createCustomAlert.LongName != createresp.LongName {
		t.Error("tag names not equal")
	}
	if createCustomAlert.Interval != createresp.Interval {
		t.Error("tag names not equal")
	}
	if createCustomAlert.Threshold != createresp.Threshold {
		t.Error("tag names not equal")
	}
	if createCustomAlert.Enabled != createresp.Enabled {
		t.Error("tag names not equal")
	}
	if createCustomAlert.Action != createresp.Action {
		t.Error("tag names not equal")
	}
	if createCustomAlert.BlockDurationSeconds != createresp.BlockDurationSeconds {
		t.Error("block durations not equal")
	}

	readresp, err := sc.GetCustomAlert(corp, site, createresp.ID)
	if err != nil {
		t.Fatal(err)
	}
	if createCustomAlert.TagName != readresp.TagName {
		t.Error("tag names not equal")
	}
	if createCustomAlert.LongName != readresp.LongName {
		t.Error("tag names not equal")
	}
	if createCustomAlert.Interval != readresp.Interval {
		t.Error("tag names not equal")
	}
	if createCustomAlert.Threshold != readresp.Threshold {
		t.Error("tag names not equal")
	}
	if createCustomAlert.Enabled != readresp.Enabled {
		t.Error("tag names not equal")
	}
	if createCustomAlert.Action != readresp.Action {
		t.Error("tag names not equal")
	}
	if createCustomAlert.BlockDurationSeconds != readresp.BlockDurationSeconds {
		t.Error("block durations not equal")
	}

	updateCustomAlert := CustomAlertBody{
		TagName:              "SQLI",
		LongName:             "Example Alert Updated",
		Interval:             10,
		Threshold:            10,
		Enabled:              true,
		Action:               "flagged",
		BlockDurationSeconds: 3600,
	}
	updateResp, err := sc.UpdateCustomAlert(corp, site, readresp.ID, updateCustomAlert)

	if err != nil {
		t.Fatal(err)
	}

	if updateCustomAlert.TagName != updateResp.TagName {
		t.Error("tag names not equal")
	}
	if updateCustomAlert.LongName != updateResp.LongName {
		t.Error("tag names not equal")
	}
	if updateCustomAlert.Interval != updateResp.Interval {
		t.Error("tag names not equal")
	}
	if updateCustomAlert.Threshold != updateResp.Threshold {
		t.Error("tag names not equal")
	}
	if updateCustomAlert.Enabled != updateResp.Enabled {
		t.Error("tag names not equal")
	}
	if updateCustomAlert.Action != updateResp.Action {
		t.Error("tag names not equal")
	}
	if updateCustomAlert.BlockDurationSeconds != updateResp.BlockDurationSeconds {
		t.Error("block durations not equal")
	}

	allalerts, err := sc.ListCustomAlerts(corp, site)
	if err != nil {
		t.Fatal(err)
	}
	if len(allalerts) != 1 {
		t.Error("alerts length incorrect. make sure none were added outside")
	}
	if updateCustomAlert.TagName != allalerts[0].TagName {
		t.Error("tag names not equal")
	}
	if updateCustomAlert.LongName != allalerts[0].LongName {
		t.Error("long names not equal")
	}
	if updateCustomAlert.Interval != allalerts[0].Interval {
		t.Error("interval not equal")
	}
	if updateCustomAlert.Threshold != allalerts[0].Threshold {
		t.Error("threshold not equal")
	}
	if updateCustomAlert.Enabled != allalerts[0].Enabled {
		t.Error("enbled not equal")
	}
	if updateCustomAlert.Action != allalerts[0].Action {
		t.Error("action not equal")
	}
	if updateCustomAlert.BlockDurationSeconds != allalerts[0].BlockDurationSeconds {
		t.Error("block durations not equal")
	}

	err = sc.DeleteCustomAlert(corp, site, createresp.ID)
	if err != nil {
		t.Fatal(err)
	}
}
func TestCreateReadUpdateDeleteCorpRule(t *testing.T) {

	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := testcreds.corp
	// Get initial counts
	initialCorps, err := sc.GetAllCorpRules(corp)
	if err != nil {
		t.Fatal(err)
	}

	createCorpRuleBody := CreateCorpRuleBody{
		SiteNames:     []string{testcreds.site},
		Type:          "signal",
		GroupOperator: "all",
		Conditions: []Condition{
			{
				Type:     "single",
				Field:    "ip",
				Operator: "equals",
				Value:    "1.2.3.4",
			},
			{
				Type:          "group",
				GroupOperator: "any",
				Conditions: []Condition{
					{
						Type:     "single",
						Field:    "ip",
						Operator: "equals",
						Value:    "5.6.7.8",
					},
				},
			},
		},
		Actions: []Action{
			{
				Type: "excludeSignal",
			},
		},
		Enabled:    true,
		Reason:     "test",
		Signal:     "SQLI",
		Expiration: "",
		CorpScope:  "specificSites",
	}
	createResp, err := sc.CreateCorpRule(corp, createCorpRuleBody)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(createCorpRuleBody, createResp.CreateCorpRuleBody) {
		t.Error("Corp rule body not equal after create")
	}

	readResp, err := sc.GetCorpRuleByID(corp, createResp.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(readResp, createResp) {
		t.Error("Corp rule body not equal after read")
	}
	updateCorpRuleBody := CreateCorpRuleBody{
		SiteNames:     []string{testcreds.site},
		Type:          "signal",
		GroupOperator: "all",
		Conditions: []Condition{
			{
				Type:     "single",
				Field:    "ip",
				Operator: "equals",
				Value:    "5.6.7.8",
			},
			{
				Type:          "group",
				GroupOperator: "any",
				Conditions: []Condition{
					{
						Type:     "single",
						Field:    "ip",
						Operator: "equals",
						Value:    "6.7.8.9",
					},
				},
			},
		},
		Actions: []Action{
			{
				Type: "excludeSignal",
			},
		},
		Enabled:    true,
		Reason:     "test",
		Signal:     "SQLI",
		Expiration: "",
		CorpScope:  "specificSites",
	}
	updateResp, err := sc.UpdateCorpRuleByID(corp, createResp.ID, updateCorpRuleBody)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(updateCorpRuleBody, updateResp.CreateCorpRuleBody) {
		t.Error("Corp rule body not equal after update")
	}
	readall, err := sc.GetAllCorpRules(corp)
	if err != nil {
		t.Fatal(err)
	}
	if len(initialCorps.Data)+1 != len(readall.Data) {
		t.Error()
	}
	if initialCorps.TotalCount+1 != readall.TotalCount {
		t.Error()
	}
	if !reflect.DeepEqual(updateCorpRuleBody, readall.Data[0].CreateCorpRuleBody) {
		t.Error("Corp rule body not equal after get all. make sure nothing was added externally")
	}
	err = sc.DeleteCorpRuleByID(corp, createResp.ID)

	if err != nil {
		t.Fatal(err)
	}
	readall, err = sc.GetAllCorpRules(corp)
	if err != nil {
		t.Fatal(err)
	}
	if len(initialCorps.Data) != len(readall.Data) {
		t.Error()
	}
	if initialCorps.TotalCount != readall.TotalCount {
		t.Error()
	}
}

func compareCorpListBody(cl1, cl2 CreateListBody) bool {
	if cl1.Name != cl2.Name {
		return false
	}
	if cl1.Type != cl2.Type {
		return false
	}
	if cl1.Description != cl2.Description {
		return false
	}
	if len(cl1.Entries) != len(cl2.Entries) {
		return false
	}
	return true
}

func TestCreateReadUpdateDeleteCorpList(t *testing.T) {
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := testcreds.corp
	createCorpListBody := CreateListBody{
		Name:        "My new List",
		Type:        "ip",
		Description: "Some IPs we are putting in a list",
		Entries: []string{
			"4.5.6.7",
			"2.3.4.5",
			"1.2.3.4",
		},
	}
	createresp, err := sc.CreateCorpList(corp, createCorpListBody)
	if err != nil {
		t.Fatal(err)
	}
	if !compareCorpListBody(createCorpListBody, createresp.CreateListBody) {
		t.Error("corp list not equal after create")
	}
	now := time.Now()
	expectedCreateResponse := ResponseListBody{
		CreateListBody: CreateListBody{
			Name:        "My new List",
			Type:        "ip",
			Description: "Some IPs we are putting in a list",
			Entries: []string{
				"4.5.6.7",
				"2.3.4.5",
				"1.2.3.4",
			},
		},
		ID:        "corp.my-new-list",
		CreatedBy: "",
		Created:   now,
		Updated:   now,
	}
	createresp.Created = now
	createresp.Updated = now
	createresp.CreatedBy = ""
	if !reflect.DeepEqual(expectedCreateResponse, createresp) {
		t.Error("corp list not equal after get")
	}

	readresp, err := sc.GetCorpListByID(corp, createresp.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !compareCorpListBody(createCorpListBody, readresp.CreateListBody) {
		t.Error("corp list not equal after read")
	}

	updateCorpListBody := UpdateListBody{
		Description: "Some IPs we are updating in the list",
		Entries: Entries{
			Additions: []string{"3.4.5.6"},
			Deletions: []string{"4.5.6.7"},
		},
	}
	updateresp, err := sc.UpdateCorpListByID(corp, readresp.ID, updateCorpListBody)
	if err != nil {
		t.Error(err)
	}

	if updateCorpListBody.Description != updateresp.Description {
		t.Error("descriptions not equal after update")
	}
	hasNewEntry := false
	for _, e := range updateresp.Entries {
		if e == "4.5.6.7" {
			t.Fail()
		}
		if e == "3.4.5.6" {
			hasNewEntry = true
		}
	}
	if !hasNewEntry {
		t.Error()
	}
	updatedCorpListBody := CreateListBody{
		Name:        "My new List",
		Type:        "ip",
		Description: "Some IPs we are updating in the list",
		Entries: []string{
			"2.3.4.5",
			"1.2.3.4",
			"3.4.5.6",
		},
	}
	if !compareCorpListBody(updatedCorpListBody, updateresp.CreateListBody) {
		t.Error("corp list not equal after update")
	}
	readall, err := sc.GetAllCorpLists(corp)
	if err != nil {
		t.Fatal(err)
	}
	if len(readall.Data) != 1 {
		t.Error()
	}
	if !compareCorpListBody(updatedCorpListBody, readall.Data[0].CreateListBody) {
		t.Error("corp list not equal after update")
	}
	err = sc.DeleteCorpListByID(corp, readresp.ID)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCreateReadUpdateDeleteCorpTag(t *testing.T) {
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := testcreds.corp
	createSignalTagBody := CreateSignalTagBody{
		ShortName:   "Example Signal Tag 1",
		Description: "An example of a custom signal tag",
	}
	createresp, err := sc.CreateCorpSignalTag(corp, createSignalTagBody)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(createSignalTagBody, createresp.CreateSignalTagBody) {
		t.Fatal()
	}
	expectedCreateResponse := ResponseSignalTagBody{
		CreateSignalTagBody: CreateSignalTagBody{
			ShortName:   "Example Signal Tag 1",
			Description: "An example of a custom signal tag",
		},
		TagName:       "corp.example-signal-tag-1",
		LongName:      "Example Signal Tag 1",
		Configurable:  false,
		Informational: false,
		NeedsResponse: false,
		CreatedBy:     "",
		Created:       time.Time{},
	}
	createresp.Created = time.Time{}
	createresp.CreatedBy = ""
	if !reflect.DeepEqual(expectedCreateResponse, createresp) {
		t.Fail()
	}
	readresp, err := sc.GetCorpSignalTagByID(corp, createresp.TagName)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(createSignalTagBody, readresp.CreateSignalTagBody) {
		t.Fail()
	}
	updateSignalTagBody := UpdateSignalTagBody{
		Description: "An example of a custom signal tag - UPDATE",
	}
	updateresp, err := sc.UpdateCorpSignalTagByID(corp, createresp.TagName, updateSignalTagBody)
	if err != nil {
		t.Fatal(err)
	}
	updatedSignalTagBody := CreateSignalTagBody{
		ShortName:   "Example Signal Tag 1",
		Description: "An example of a custom signal tag - UPDATE",
	}
	if !reflect.DeepEqual(updatedSignalTagBody, updateresp.CreateSignalTagBody) {
		t.Fail()
	}
	readall, err := sc.GetAllCorpSignalTags(corp)
	if err != nil {
		t.Fatal(err)
	}
	if len(readall.Data) != 1 {
		t.Fail()
	}
	if !reflect.DeepEqual(updatedSignalTagBody, readall.Data[0].CreateSignalTagBody) {
		t.Fail()
	}
	err = sc.DeleteCorpSignalTagByID(corp, readresp.TagName)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCreateReadUpdateDeleteSignalTag(t *testing.T) {
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := testcreds.corp
	site := testcreds.site
	createSignalTagBody := CreateSignalTagBody{
		ShortName:   "example-signal-tag",
		Description: "An example of a custom signal tag",
	}
	createresp, err := sc.CreateSiteSignalTag(corp, site, createSignalTagBody)
	if err != nil {
		t.Fatal(err)
	}
	readresp, err := sc.GetSiteSignalTagByID(corp, site, createresp.TagName)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(createSignalTagBody, readresp.CreateSignalTagBody) {
		t.Fail()
	}
	updateSignalTagBody := UpdateSignalTagBody{
		Description: "An example of a custom signal tag - UPDATE",
	}
	updateresp, err := sc.UpdateSiteSignalTagByID(corp, site, createresp.TagName, updateSignalTagBody)
	if err != nil {
		t.Fatal(err)
	}
	updatedSignalTagBody := CreateSignalTagBody{
		ShortName:   "example-signal-tag",
		Description: "An example of a custom signal tag - UPDATE",
	}
	if !reflect.DeepEqual(updatedSignalTagBody, updateresp.CreateSignalTagBody) {
		t.Fail()
	}
	readall, err := sc.GetAllSiteSignalTags(corp, site)
	if err != nil {
		t.Fatal(err)
	}
	if len(readall.Data) != 1 {
		t.Fail()
	}
	if !reflect.DeepEqual(updatedSignalTagBody, readall.Data[0].CreateSignalTagBody) {
		t.Fail()
	}
	err = sc.DeleteSiteSignalTagByID(corp, site, readresp.TagName)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCreateReadUpdateDeleteSiteTemplate(t *testing.T) {
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := testcreds.corp
	site := testcreds.site
	createresp, err := sc.UpdateSiteTemplateRuleByID(corp, site, "LOGINATTEMPT", SiteTemplateRuleBody{
		DetectionAdds: []Detection{
			{
				DetectionUpdateBody: DetectionUpdateBody{
					Name:    "path",
					Enabled: true,
					Fields: []ConfiguredDetectionField{
						{
							Name:  "path",
							Value: "/auth/*",
						},
					},
				},
			},
		},
		DetectionUpdates: []Detection{},
		DetectionDeletes: []Detection{},
		AlertAdds: []Alert{
			{
				AlertUpdateBody: AlertUpdateBody{
					LongName:             "LOGINATTEMPT-50-in-1",
					Interval:             1,
					Threshold:            50,
					SkipNotifications:    true,
					Enabled:              true,
					Action:               "info",
					BlockDurationSeconds: 99677,
				}},
		},
		AlertUpdates: []Alert{},
		AlertDeletes: []Alert{},
	})
	if err != nil {
		t.Fatal(err)
	}
	readresp, err := sc.GetSiteTemplateRuleByID(corp, site, createresp.Name)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(createresp)
	fmt.Println(readresp)
}

func TestCRUDCorpIntegrations(t *testing.T) {
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := testcreds.corp

	url := "https://www.signalsciences.com"

	createResp, err := sc.AddCorpIntegration(corp, IntegrationBody{
		URL:    url,
		Type:   "slack",
		Events: []string{"webhookEvents"},
	})
	if err != nil {
		t.Fatal(err)
	}

	readResp, err := sc.GetCorpIntegration(corp, createResp.ID)
	if err != nil {
		t.Fatal(err)
	}
	if createResp.ID != readResp.ID {
		t.Fail()
	}
	if createResp.URL != readResp.URL {
		t.Fail()
	}
	if createResp.Type != readResp.Type {
		t.Fail()
	}
	if !reflect.DeepEqual([]string{"webhookEvents"}, readResp.Events) {
		t.Fail()
	}

	newURL := url + "/blah"
	err = sc.UpdateCorpIntegration(corp, readResp.ID, UpdateIntegrationBody{
		URL:    newURL,
		Events: []string{"corpUpdated", "listDeleted"},
	})
	if err != nil {
		t.Fatal(err)
	}
	readResp2, err := sc.GetCorpIntegration(corp, createResp.ID)
	if err != nil {
		t.Fatal(err)
	}
	if newURL != readResp2.URL {
		t.Fail()
	}
	if !reflect.DeepEqual([]string{"corpUpdated", "listDeleted"}, readResp2.Events) {
		t.Fail()
	}

	err = sc.DeleteCorpIntegration(corp, readResp2.ID)
	if err != nil {
		t.Fatal(err)
	}
}

// TestCRUDListRestartCloudWAFInstance is an optional test. To run it, the environment variable `SIGSCI_TEST_CLOUDWAFINSTANCE`
// must be set to a true value recognized by `strconv.ParseBool`. Additionally, to pass, the `go test` timeout must be
// increased from the default 10m value, e.g. `go test -timeout 30m`. The `TestCRUDListRestartCloudWAFInstance` test by itself
// has been known to run for 750.88s.
func TestCRUDListRestartCloudWAFInstance(t *testing.T) {
	if !testcreds.testCloudWAFInstance {
		return
	}

	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := testcreds.corp
	site := testcreds.site

	durationDeploymentTimeout := 30 * time.Minute
	durationPendingInstanceCheck := 20 * time.Second
	statusDone := "done"

	var createCWAFResponse CloudWAFInstance
	var err error
	createCWAFRequest := CloudWAFInstanceBody{
		Name:                    "Test Cloud WAF Instance - Go SDK Test",
		Description:             "Test Cloud WAF Instance created at " + time.Now().UTC().Format(time.RFC3339),
		Region:                  "us-west-1",
		TLSMinVersion:           "1.2",
		UseUploadedCertificates: false,
		WorkspaceConfigs: []CloudWAFInstanceWorkspaceConfig{{
			SiteName:          site,
			InstanceLocation:  "advanced",
			ClientIPHeader:    "Fastly-Client-IP",
			ListenerProtocols: []string{"https"},
			Routes: []CloudWAFInstanceWorkspaceRoute{{
				Domains:           []string{"example.net"},
				Origin:            "https://example.com",
				ConnectionPooling: true,
				TLSHostOverride:   true,
			}},
		}},
	}

	ctx, cancel := context.WithTimeout(context.Background(), durationDeploymentTimeout)
	for {
		createCWAFResponse, err = sc.CreateCloudWAFInstance(corp, createCWAFRequest)
		if err == nil {
			cancel()
			break
		} else if err.Error() != "cannot create with pending instance" {
			t.Fatal(err)
		} else {
			if ctx.Err() != nil {
				t.Skip("call to CreateCloudWAFInstance blocked by pending instance that did not complete before timeout.")
			}
			time.Sleep(durationPendingInstanceCheck)
			continue
		}
	}

	if createCWAFRequest.Name != createCWAFResponse.Name {
		t.Fail()
	}

	// `description`` is not populated in response
	// `tls_min_version`` initially set to `unknown_tls_min` in create response.

	if createCWAFRequest.Region != createCWAFResponse.Region {
		t.Fail()
	}
	if createCWAFRequest.UseUploadedCertificates != createCWAFResponse.UseUploadedCertificates {
		t.Fail()
	}

	var readCWAF CloudWAFInstance
	ctx, cancel = context.WithTimeout(context.Background(), durationDeploymentTimeout)
	defer cancel()
	for {
		readCWAF, err = sc.GetCloudWAFInstance(corp, createCWAFResponse.ID)
		if err != nil {
			t.Fatal(err)
		}
		if createCWAFResponse.ID != readCWAF.ID {
			t.Fail()
		}
		if createCWAFRequest.Name != readCWAF.Name {
			t.Fail()
		}
		if createCWAFRequest.Description != readCWAF.Description {
			t.Fail()
		}
		if createCWAFRequest.Region != readCWAF.Region {
			t.Fail()
		}
		if createCWAFRequest.TLSMinVersion != readCWAF.TLSMinVersion {
			t.Fail()
		}
		if createCWAFRequest.UseUploadedCertificates != readCWAF.UseUploadedCertificates {
			t.Fail()
		}
		if len(createCWAFRequest.WorkspaceConfigs) != len(readCWAF.WorkspaceConfigs) {
			t.Fail()
		}
		if readCWAF.Deployment.Status == statusDone {
			cancel()
			break
		}
		if ctx.Err() != nil {
			t.Skip("call to CreateCloudWAFInstance did not complete before timeout.")
		}
		time.Sleep(durationPendingInstanceCheck)
	}

	readCWAFs, err := sc.ListCloudWAFInstances(corp)
	if err != nil {
		t.Fatal(err)
	}
	if len(readCWAFs) == 0 {
		t.Fail()
	}
	for _, cwaf := range readCWAFs {
		if len(strings.TrimSpace(cwaf.ID)) == 0 {
			t.Fail()
		}
	}

	var updateCWAF CloudWAFInstanceBody
	j, err := json.Marshal(readCWAF)
	if err != nil {
		t.Fatal(err)
	}
	err = json.Unmarshal(j, &updateCWAF)
	if err != nil {
		t.Fatal(err)
	}
	newDesc := "Test Cloud WAF Instance updated at " + time.Now().UTC().Format(time.RFC3339)
	updateCWAF.Description = newDesc

	err = sc.UpdateCloudWAFInstance(corp, readCWAF.ID, updateCWAF)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel = context.WithTimeout(context.Background(), durationDeploymentTimeout)
	defer cancel()
	for {
		readCWAF2, err := sc.GetCloudWAFInstance(corp, readCWAF.ID)
		if err != nil {
			t.Fatal(err)
		}
		if createCWAFResponse.ID != readCWAF2.ID {
			t.Fail()
		}
		if newDesc != readCWAF2.Description {
			t.Fail()
		}
		if readCWAF2.Deployment.Status == statusDone {
			cancel()
			break
		}
		if ctx.Err() != nil {
			t.Skip("call to UpdateCloudWAFInstance did not complete before timeout.")
		}
		time.Sleep(durationPendingInstanceCheck)
	}

	// Executing restart will cause test to exceed 10 minutes, use `go test -timeout 30m ...` to increase timeout.
	err = sc.RestartCloudWAFInstance(corp, readCWAF.ID)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel = context.WithTimeout(context.Background(), durationDeploymentTimeout)
	defer cancel()
	for {
		readCWAF3, err := sc.GetCloudWAFInstance(corp, readCWAF.ID)
		if err != nil {
			t.Fatal(err)
		}
		if readCWAF3.Deployment.Status == statusDone {
			cancel()
			break
		}
		if ctx.Err() != nil {
			t.Skip("call to RestartCloudWAFInstance did not complete before timeout.")
		}
		time.Sleep(durationPendingInstanceCheck)
	}

	err = sc.DeleteCloudWAFInstance(corp, readCWAF.ID)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCRUDListCloudWAFCertificate(t *testing.T) {
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := testcreds.corp

	createReqBody := UploadCloudWAFCertificateBody{
		CloudWAFCertificateBase: CloudWAFCertificateBase{
			Name:            "Go SDK - Create Test - www.example.com",
			CertificateBody: "-----BEGIN CERTIFICATE-----\nMIICzDCCAbQCCQDV2NzCr6aPbDANBgkqhkiG9w0BAQsFADAoMQwwCgYDVQQLDAN3\nZWIxGDAWBgNVBAMMD3d3dy5leGFtcGxlLmNvbTAeFw0yMjA5MDMxNzE5MTVaFw0z\nMjA4MzExNzE5MTVaMCgxDDAKBgNVBAsMA3dlYjEYMBYGA1UEAwwPd3d3LmV4YW1w\nbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3xLllGg3Kl0S\nW16pOwH4VXyGTyByWk3gShoSnEXqWYwoGDF18YhGFFMYLUBNfbDG/jy8MLiKY20R\nBhV5hpObd4ZQq4PIlTl4ZNKy07CUPX/AufdbQzrFCQy96lXBVjo6gR10TD+F/CjC\ntOkM83dxtZoSPzH86eHteos41+apjgpfvVai3vkBNuZeeoxuERkxuGsfpcK2qWTg\nZFuncrWt6Plvlu70qGEIPtiFiPfQ8Rs2mdzKJEBC8nb4nqSWxIbY9Z87yS3X3C/A\n0xr0W4YxOLyCN94qr+Cc3Zl6DvjOv3LWAfv4qFXApWD9f8ynAzjojqfnXtavV6+D\n1SOdvMcTVQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQDG9lhmTU9EzE/B7hAhNPj2\nLHlRPj8ASnSpxBzWn6Acyu9hHJbGhkR8BnRPPjihH8kv+zRaRVYxhG2sb99qg168\nrPKWMbZI6ZvCQGKNjLpwUARwPOKeZ8zF+qyzxdpM9mMyzx9SI1QXDirA0BsUbAjm\nRfioqCdT54F8gFrH1+AnUX4Kf2euTS65bHRgegDiIsrAmwcRrzC8ev1SDiPMUkyC\ngoD1A0LHXLN1LMTs6qBXIkbCjYNRkPZBRagEu68CkwjT5H4vBIl39+Lcvo2WCBSG\nj4LzHGcDief95tMLhz0f5g0geV3ytrld5NSw0g1sEYJlDe8NA/aDi4gVviOt3Z5A\n-----END CERTIFICATE-----\n",
		},
		PrivateKey: "-----BEGIN PRIVATE KEY-----\nMIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQDfEuWUaDcqXRJb\nXqk7AfhVfIZPIHJaTeBKGhKcRepZjCgYMXXxiEYUUxgtQE19sMb+PLwwuIpjbREG\nFXmGk5t3hlCrg8iVOXhk0rLTsJQ9f8C591tDOsUJDL3qVcFWOjqBHXRMP4X8KMK0\n6Qzzd3G1mhI/Mfzp4e16izjX5qmOCl+9VqLe+QE25l56jG4RGTG4ax+lwrapZOBk\nW6dyta3o+W+W7vSoYQg+2IWI99DxGzaZ3MokQELydviepJbEhtj1nzvJLdfcL8DT\nGvRbhjE4vII33iqv4JzdmXoO+M6/ctYB+/ioVcClYP1/zKcDOOiOp+de1q9Xr4PV\nI528xxNVAgMBAAECggEBAKPsP/aJipg/4oBwFE2/SdyP8CZvQnjnpzzs4eYiXm7F\nVqVIm1INAOpokWiXSxpk8CXdPbFTuqYLfKoK182z5Fe1xMv0wE4f+D+msTBsHtL+\ncQJ3KYJCyo225kwwDi2uBlXg7hglyfCdh07nvtOeX1nCyUvVEPRRSHB3pCLLZqdv\nysCCL4Sowuebcpec3w3nCuMTg+L1nxdk25C53EjsYGqMQgq0YX/CTo+M2X2Infac\n3Ig5bkQohaOz724L7mc63UaT9m36vgEUZfwndxxVUBHzxQ/tqr/O4XEKmSdFrExh\nyw+YFyP43WcE0m1lc2hYHKEwTM1QF1nVY60fyPJ0zCECgYEA9ljzLd8OjXKbhK7S\nHZWZyR1+Lo4HnrBsLgCJVIuGuWi6gDi8hsarYpTe8RVhgqBaudMpK+Eup76WuMBt\nF9RVpzkNBE7T+p1jkmCWOIkCpvf2/IoqlZ1ao5qu1fhK5HpnsYCTmUHhJmid3da9\neT34oR2WnvJ9s6fvqC1C6URtsE0CgYEA59B+pvJxvV8klPDfIgN31bcR90srHJTJ\nST3lnVMJNND6PJ3D96YJSHV0EIotqyXlv/droqerhNJ+gNOHvrXMKTJ7udCDQKfW\n6IFiWaRW1SkqUEXlv59JI6Ip3B9Rfi3w3rPhNLAi/7GjSm33C+OgsMVq9ZBTMjR6\nqnS872CwsykCgYEAq22+3D8K+3ezraOSaDAA8qlpc7A2sUGIJoMNDh6CRGgS0MOq\nvgdmoJWEhzQfxS0dtY6yaeyr8ON6M1sFD74dVN8opcTNUutPrT81imYdyF9qKtdj\nRvZXat5rqE6+nzxnCGi3TcFAkt/ea8/RzptHd6cFd9q7itfkuJ22oGmUA0kCgYEA\nzmvUO+kr6wtr0czjhLA952rLbr/ateqviq65ZmxoiEWGbq+1rzKElacxIQFKRVrL\nyTMS/5X6n52o1CKIgAP2tsCjeAT6u3o5XnTIFTbHs6yiZzS2rvmx8S8Xw1GICanz\nEPxwj7BAmhueYkqlcErT7lT9N4m667vbdynYi/g3oHECgYEA5dCjPFl94ZGStHF2\n4+cI1NCbVTnQApFI1+Vmd4lED619KSnpk/77TaYTh2I8gsK3OZP4crvee5aL41TJ\nY20XmAq/Dvv3g7QR97ND/AghEU8nnpZo1fgHzCcyZSkaBzMFeYdsfaGDncM56I0B\n65yblwYq9Vyzy3hBFY6XGaFdnZ0=\n-----END PRIVATE KEY-----\n",
	}

	createResp, err := sc.UploadCloudWAFCertificate(corp, createReqBody)
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.TrimSpace(createResp.ID)) == 0 {
		t.Fail()
	}

	readResp, err := sc.GetCloudWAFCertificate(corp, createResp.ID)
	if err != nil {
		t.Fatal(err)
	}
	if readResp.ID != createResp.ID {
		t.Fail()
	}
	if readResp.CertificateBody != createReqBody.CertificateBody {
		t.Fail()
	}
	if readResp.CertificateChain != createReqBody.CertificateChain {
		t.Fail()
	}
	if readResp.CommonName != "www.example.com" {
		t.Fail()
	}
	if len(readResp.Domains) != 1 || readResp.Domains[0] != "www.example.com" {
		t.Fail()
	}
	if readResp.ExpiresAt != "2032-08-31T17:19:15Z" {
		t.Fail()
	}
	if readResp.Fingerprint != "d3d246a79291ce3448f13b99d34d09066861c71a" {
		t.Fail()
	}
	if readResp.Name != createReqBody.Name {
		t.Fail()
	}
	if readResp.Status != "active" {
		t.Fail()
	}
	if len(readResp.SubjectAlternativeNames) != 0 {
		t.Fail()
	}

	listResp, err := sc.ListCloudWAFCertificates(corp)
	if err != nil {
		t.Fatal(err)
	}
	if len(listResp) == 0 {
		t.Fail()
	}

	updateName := "Go SDK - Update Test - www.example.com"
	updateResp, err := sc.UpdateCloudWAFCertificate(corp, createResp.ID, UpdateCloudWAFCertificateBody{
		Name: updateName,
	})
	if err != nil {
		t.Fatal(err)
	}
	if updateResp.Name != updateName {
		t.Fail()
	}
	if updateResp.ID != createResp.ID {
		t.Fail()
	}
	if updateResp.Fingerprint != "d3d246a79291ce3448f13b99d34d09066861c71a" {
		t.Fail()
	}

	err = sc.DeleteCloudWAFCertificate(corp, createResp.ID)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCRUDSiteMonitorDashboard(t *testing.T) {
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := testcreds.corp
	site := testcreds.site

	createResp, err := sc.GenerateSiteMonitorDashboard(corp, site, "000000000000000000000001")
	if err != nil {
		t.Fatal(err)
	}

	monitors, err := sc.GetSiteMonitor(corp, site, createResp.ID)
	if err != nil {
		t.Fatal(err)
	}
	var monitor SiteMonitor
	for _, m := range monitors {
		if m.ID == createResp.ID {
			monitor = m
		}
	}
	if monitor.ID == "" {
		t.Fatal("couldnt find newly created site monitor")
	}
	if createResp.ID != monitor.ID {
		t.Fail()
	}
	if createResp.URL != monitor.URL {
		t.Fail()
	}
	if createResp.Share != monitor.Share {
		t.Fail()
	}

	err = sc.UpdateSiteMonitor(corp, site, createResp.ID, UpdateSiteMonitorBody{
		ID:    createResp.ID,
		Share: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	monitors2, err := sc.GetSiteMonitor(corp, site, createResp.ID)
	if err != nil {
		t.Fatal(err)
	}
	var monitor2 SiteMonitor
	for _, m := range monitors2 {
		if m.ID == createResp.ID {
			monitor2 = m
		}
	}
	if monitor2.ID == "" {
		t.Fatal("couldnt find newly created site monitor")
	}

	if createResp.ID != monitor2.ID {
		t.Fail()
	}
	if createResp.URL != monitor2.URL {
		t.Fail()
	}
	if monitor2.Share != false {
		t.Fail()
	}

	err = sc.DeleteSiteMonitor(corp, site, createResp.ID)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCRUDSiteMonitor(t *testing.T) {
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := testcreds.corp
	site := testcreds.site

	createResp, err := sc.GenerateSiteMonitor(corp, site)
	if err != nil {
		t.Fatal(err)
	}

	monitors, err := sc.GetSiteMonitor(corp, site, createResp.ID)
	if err != nil {
		t.Fatal(err)
	}
	var monitor SiteMonitor
	for _, m := range monitors {
		if m.ID == createResp.ID {
			monitor = m
		}
	}
	if monitor.ID == "" {
		t.Fatal("couldnt find newly created site monitor")
	}
	if createResp.ID != monitor.ID {
		t.Fail()
	}
	if createResp.URL != monitor.URL {
		t.Fail()
	}
	if createResp.Share != monitor.Share {
		t.Fail()
	}

	err = sc.UpdateSiteMonitor(corp, site, createResp.ID, UpdateSiteMonitorBody{
		ID:    createResp.ID,
		Share: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	monitors2, err := sc.GetSiteMonitor(corp, site, createResp.ID)
	if err != nil {
		t.Fatal(err)
	}
	var monitor2 SiteMonitor
	for _, m := range monitors2 {
		if m.ID == createResp.ID {
			monitor2 = m
		}
	}
	if monitor2.ID == "" {
		t.Fatal("couldnt find newly created site monitor")
	}
	if createResp.ID != monitor2.ID {
		t.Fail()
	}
	if createResp.URL != monitor2.URL {
		t.Fail()
	}
	if monitor2.Share != false {
		t.Fail()
	}

	err = sc.DeleteSiteMonitor(corp, site, createResp.ID)
	if err != nil {
		t.Fatal(err)
	}
}

func TestClient_GetSitePrimaryAgentKey(t *testing.T) {
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := testcreds.corp
	site := testcreds.site

	keysResponse, err := sc.GetSitePrimaryAgentKey(corp, site)
	if err != nil {
		t.Fatal(err)
	}
	if keysResponse.Name != site {
		t.Error("primary key name should be the same as site name")
	}
	if keysResponse.AccessKey == "" {
		t.Error("Expected access key to be populated")
	}
	if keysResponse.SecretKey == "" {
		t.Error("Expected secret key to be populated")
	}
}

func TestCreateSiteRulesResponseCode(t *testing.T) {
	createSiteRulesBody := CreateSiteRuleBody{
		Type:          "request",
		GroupOperator: "all",
		Enabled:       true,
		Reason:        "Example site rule",
		Expiration:    "",
		Conditions: []Condition{
			{
				Type:     "single",
				Field:    "ip",
				Operator: "equals",
				Value:    "1.2.3.4",
			},
		},
		Actions: []Action{
			{
				Type:         "block",
				ResponseCode: 499,
			},
		},
	}
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := testcreds.corp
	site := testcreds.site
	createResp, err := sc.CreateSiteRule(corp, site, createSiteRulesBody)
	if err != nil {
		t.Fatal(err)
	}
	if len(createResp.CreateSiteRuleBody.Actions) > 0 && createResp.CreateSiteRuleBody.Actions[0].ResponseCode != 499 {
		t.Errorf("expected response code to be 499")
	}
	if !compareSiteRuleBody(createSiteRulesBody, createResp.CreateSiteRuleBody) {
		t.Errorf("CreateSiteRulesgot: %v expected %v", createResp, createSiteRulesBody)
	}

	readResp, err := sc.GetSiteRuleByID(corp, site, createResp.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !compareSiteRuleBody(createSiteRulesBody, readResp.CreateSiteRuleBody) {
		t.Errorf("CreateSiteRulesgot: %v expected %v", createResp, createSiteRulesBody)
	}
	updateSiteRuleBody := CreateSiteRuleBody{
		Type:          "request",
		GroupOperator: "all",
		Enabled:       true,
		Reason:        "Example site rule",
		Expiration:    "",
		Conditions: []Condition{
			{
				Type:     "single",
				Field:    "ip",
				Operator: "equals",
				Value:    "1.2.3.4",
			},
		},
		Actions: []Action{
			{
				Type:         "block",
				ResponseCode: 418,
			},
		},
	}
	updateResp, err := sc.UpdateSiteRuleByID(corp, site, createResp.ID, updateSiteRuleBody)
	if err != nil {
		t.Fatal(err)
	}
	if len(updateResp.CreateSiteRuleBody.Actions) > 0 && updateResp.CreateSiteRuleBody.Actions[0].ResponseCode != 418 {
		t.Errorf("expected response code to be 418, I'm a teapot.")
	}
	if !compareSiteRuleBody(updateSiteRuleBody, updateResp.CreateSiteRuleBody) {
		t.Errorf("CreateSiteRules got: %v expected %v", updateResp, updateSiteRuleBody)
	}

	err = sc.DeleteSiteRuleByID(corp, site, createResp.ID)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCreateSiteRulesRateLimitClientIdentifiers(t *testing.T) {
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := testcreds.corp
	site := testcreds.site

	// A test signal is needed for the request, make this first
	createSignalTagBody := CreateSignalTagBody{
		ShortName:   "client-ident-signal-tag",
		Description: "An example of a custom signal tag",
	}
	createSignalresp, err := sc.CreateSiteSignalTag(corp, site, createSignalTagBody)
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		err := sc.DeleteSiteSignalTagByID(corp, site, createSignalresp.TagName)
		if err != nil {
			fmt.Printf("Failed to delete tag %s, you might have to do this manually in the console\n", createSignalresp.TagName)
		}
	}()

	// Create Request body with client identifiers in it
	createSiteRulesBody := CreateSiteRuleBody{
		Type:          "rateLimit",
		GroupOperator: "all",
		Enabled:       true,
		Reason:        "Example site rule with client identifiers",
		Expiration:    "",
		Signal:        createSignalresp.TagName,
		Conditions: []Condition{
			{
				Type:     "single",
				Field:    "ip",
				Operator: "equals",
				Value:    "1.2.3.4",
			},
		},
		Actions: []Action{
			{
				Type:   "logRequest",
				Signal: createSignalresp.TagName,
			},
		},
		RateLimit: &RateLimit{
			Threshold: 100,
			Interval:  1,
			Duration:  600,
			ClientIdentifiers: []ClientIdentifier{
				{
					Key:  "anything",
					Name: "somethingelse",
					Type: "requestHeader",
				},
			},
		},
	}

	createResp, err := sc.CreateSiteRule(corp, site, createSiteRulesBody)
	if err != nil {
		t.Fatal(err)
	}
	if createResp.RateLimit.ClientIdentifiers == nil || len(createResp.RateLimit.ClientIdentifiers) != 1 {
		t.Errorf("expected one client identifier")
	}

	readResp, err := sc.GetSiteRuleByID(corp, site, createResp.ID)
	if err != nil {
		t.Fatal(err)
	}
	if readResp.RateLimit.ClientIdentifiers == nil || len(readResp.RateLimit.ClientIdentifiers) != 1 {
		t.Errorf("Expected to receive one client identifier back")
	}

	err = sc.DeleteSiteRuleByID(corp, site, createResp.ID)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCRUDSiteRequestRule(t *testing.T) {
	createSiteRulesBody := CreateSiteRuleBody{
		Type:           "request",
		GroupOperator:  "all",
		Enabled:        true,
		Reason:         "Example site rule",
		RequestLogging: "none",
		Expiration:     "",
		Conditions: []Condition{
			{
				Type:     "single",
				Field:    "ip",
				Operator: "equals",
				Value:    "1.2.3.4",
			},
			{
				Type:          "group",
				GroupOperator: "any",
				Conditions: []Condition{
					{
						Type:     "single",
						Field:    "ip",
						Operator: "equals",
						Value:    "5.6.7.8",
					},
				},
			},
		},
		Actions: []Action{
			{
				Type: "block",
			},
		},
	}

	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := testcreds.corp
	site := testcreds.site

	createResp, err := sc.CreateSiteRule(corp, site, createSiteRulesBody)
	if err != nil {
		t.Fatal(err)
	}

	if !compareSiteRuleBody(createSiteRulesBody, createResp.CreateSiteRuleBody) {
		t.Errorf("CreateSiteRules got:\n %#v\n want\n %#v", createResp, createSiteRulesBody)
	}

	readResp, err := sc.GetSiteRuleByID(corp, site, createResp.ID)
	if err != nil {
		t.Fatal(err)
	}

	if !compareSiteRuleBody(createSiteRulesBody, readResp.CreateSiteRuleBody) {
		t.Errorf("CreateSiteRules got:\n %#v\n want\n %#v", createResp, createSiteRulesBody)
	}

	updateSiteRuleBody := createSiteRulesBody
	updateSiteRuleBody.Reason = "a new reason"

	updateResp, err := sc.UpdateSiteRuleByID(corp, site, createResp.ID, updateSiteRuleBody)
	if err != nil {
		t.Fatal(err)
	}

	if !compareSiteRuleBody(updateSiteRuleBody, updateResp.CreateSiteRuleBody) {
		t.Errorf("CreateSiteRules got:\n %#v\n want %#v", updateResp, updateSiteRuleBody)
	}

	readall, err := sc.GetAllSiteRules(corp, site)
	if err != nil {
		t.Fatal(err)
	}

	if len(readall.Data) != 0 {
		t.Error()
	}

	if readall.TotalCount != 0 {
		t.Error()
	}

	foundUpdatedRule := false
	for _, r := range readall.Data {
		if r.ID == updateResp.ID {
			foundUpdatedRule = true
		}
	}
	if !foundUpdatedRule {
		t.Error("updated rule not found in GetAllSiteRules")
	}

	err = sc.DeleteSiteRuleByID(corp, site, createResp.ID)
	if err != nil {
		t.Fatal(err)
	}
}
