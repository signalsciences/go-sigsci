package sigsci

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"reflect"
	"testing"
	"time"
)

type TestCreds struct {
	email string
	token string
	corp  string
	site  string
}

var testcreds = TestCreds{
	email: os.Getenv("SIGSCI_EMAIL"),
	token: os.Getenv("SIGSCI_TOKEN"),
	corp:  os.Getenv("SIGSCI_CORP"),
	site:  os.Getenv("SIGSCI_SITE"),
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
	if "Test Site" != siteresponse.DisplayName {
		t.Errorf("Displayname got %s expected %s", siteresponse.DisplayName, "Test Site")
	}
	if "block" != siteresponse.AgentLevel {
		t.Errorf("AgentLevel got %s expected %s", siteresponse.AgentLevel, "block")
	}
	if 406 != siteresponse.BlockHTTPCode {
		t.Errorf("BlockHTTPCode got %d expected %d", siteresponse.BlockHTTPCode, 406)
	}
	if 86400 != siteresponse.BlockDurationSeconds {
		t.Errorf("BlockDurationSeconds got %d expected %d", siteresponse.BlockDurationSeconds, 86400)
	}
	if "" != siteresponse.AgentAnonMode {
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

	if "Test Site 2" != updateSite.DisplayName {
		t.Errorf("Displayname got %s expected %s", updateSite.DisplayName, "Test Site 2")
	}
	if "off" != updateSite.AgentLevel {
		t.Errorf("AgentLevel got %s expected %s", updateSite.AgentLevel, "off")
	}
	if 406 != updateSite.BlockHTTPCode {
		t.Errorf("BlockHTTPCode got %d expected %d", updateSite.BlockHTTPCode, 406)
	}
	if 86402 != updateSite.BlockDurationSeconds {
		t.Errorf("BlockDurationSeconds got %d expected %d", updateSite.BlockDurationSeconds, 86402)
	}
	if "EU" != updateSite.AgentAnonMode {
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

func compareSiteListBody(sl1, sl2 CreateListBody) bool {
	if sl1.Type != sl2.Type {
		return false
	}
	if sl1.Description != sl2.Description {
		return false
	}
	if sl1.Name != sl2.Name {
		return false
	}
	if len(sl1.Entries) != len(sl2.Entries) {
		return false
	}
	return true
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
		TagName:   "SQLI",
		LongName:  "Example Alert",
		Interval:  1,
		Threshold: 10,
		Enabled:   true,
		Action:    "flagged",
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

	updateCustomAlert := CustomAlertBody{
		TagName:   "SQLI",
		LongName:  "Example Alert Updated",
		Interval:  10,
		Threshold: 10,
		Enabled:   true,
		Action:    "flagged",
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

	allalerts, err := sc.ListCustomAlerts(corp, site)
	if err != nil {
		t.Fatal(err)
	}
	if len(allalerts) != 1 {
		t.Error("alerts length incorrect. make sure none we added outside")
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
