package sigsci

import (
	"encoding/json"
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

type TestCreds struct {
	email string
	token string
}

var testcreds = TestCreds{
	email: os.Getenv("SIGSCI_EMAIL"),
	token: os.Getenv("SIGSCI_TOKEN"), //"6b62cee3-bd06-487e-9283-d565078b7a8f",
}

func ExampleClient_InviteUser() {
	email := testcreds.email
	password := testcreds.token
	sc, err := NewClient(email, password)
	if err != nil {
		log.Fatal(err)
	}

	invite := NewCorpUserInvite(RoleCorpUser, []SiteMembership{
		NewSiteMembership("www.mysite.com", RoleSiteOwner),
	})

	_, err = sc.InviteUser("testcorp", "test@test.net", invite)
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
				assert.Equal(t, "splunk-testcorp", corps[0].Name)
			}
		})
	}
}
func TestCreateDeleteSite(t *testing.T) {
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := "splunk-testcorp"

	siteBody := CreateSiteBody{
		Name:                 "janitha-test-site",
		DisplayName:          "Janitha Test Site",
		AgentLevel:           "Log",
		BlockHTTPCode:        406,
		BlockDurationSeconds: 86400,
		AgentAnonMode:        "",
	}
	siteresponse, err := sc.CreateSite(corp, siteBody)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "Janitha Test Site", siteresponse.DisplayName)
	err = sc.DeleteSite(corp, siteBody.Name)
	if err != nil {
		t.Logf("%#v", err)
	}
}
func TestGetAlerts(t *testing.T) {
	t.Skip()
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := "splunk-tescorp"
	site := "splunk-test"
	alert, err := sc.GetCustomAlert(corp, site, "5e828777a981ef01c7107035")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", alert)
}
func TestCreateCustomSiteAlert(t *testing.T) {
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := "splunk-tescorp"
	site := "splunk-test"
	customAlertBody := CustomAlertBody{
		TagName:   "CMDEXE",
		LongName:  "Janitha Long Name",
		Action:    "flagged",
		Enabled:   true,
		Interval:  1,
		Threshold: 1,
	}
	alert, err := sc.CreateCustomAlert(corp, site, customAlertBody) //changed the method to POST
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, alert.Enabled)
	customAlertBody = CustomAlertBody{
		TagName:   "CMDEXE",
		LongName:  "Janitha Long Name",
		Action:    "flagged",
		Enabled:   false,
		Interval:  1,
		Threshold: 1,
	}
	alertup, err := sc.UpdateCustomAlert(corp, site, alert.ID, customAlertBody)
	assert.Equal(t, false, alertup.Enabled)
	assert.Equal(t, alert.ID, alertup.ID)
	err = sc.DeleteCustomAlert(corp, site, alert.ID)
	_, err = sc.GetCustomAlert(corp, site, alert.ID)
	if err == nil { //expect a failure because the ID does not exist
		t.Fatal(err)
	}
	// assert.Equal(t, alert.ID, alertdel.ID)
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
			Condition{
				Type:     "single",
				Field:    "ip",
				Operator: "equals",
				Value:    "1.2.3.4",
			},
			Condition{
				Type:          "group",
				GroupOperator: "any",
				Conditions: []Condition{
					Condition{
						Type:     "single",
						Field:    "ip",
						Operator: "equals",
						Value:    "5.6.7.8",
					},
				},
			},
		},
		Actions: []Action{
			Action{
				Type: "excludeSignal",
			},
		},
	}
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := "splunk-tescorp"
	site := "splunk-test"
	createResp, err := sc.CreateSiteRule(corp, site, createSiteRulesBody)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, createSiteRulesBody, *createResp.CreateSiteRuleBody)

	readResp, err := sc.GetSiteRuleByID(corp, site, createResp.ID)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, createSiteRulesBody, *readResp.CreateSiteRuleBody)
	updateSiteRuleBody := CreateSiteRuleBody{
		Type:          "signal",
		GroupOperator: "all",
		Enabled:       true,
		Reason:        "Example site rule",
		Signal:        "SQLI",
		Expiration:    "",
		Conditions: []Condition{
			Condition{
				Type:     "single",
				Field:    "ip",
				Operator: "equals",
				Value:    "1.2.3.4",
			},
			Condition{
				Type:          "group",
				GroupOperator: "any",
				Conditions: []Condition{
					Condition{
						Type:     "single",
						Field:    "ip",
						Operator: "equals",
						Value:    "9.10.11.12",
					},
				},
			},
		},
		Actions: []Action{
			Action{
				Type: "excludeSignal",
			},
		},
	}
	updateResp, err := sc.UpdateSiteRuleByID(corp, site, createResp.ID, updateSiteRuleBody)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, updateSiteRuleBody, *updateResp.CreateSiteRuleBody)

	readall, err := sc.GetAllSiteRules(corp, site)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 1, len(readall.Data))
	assert.Equal(t, 1, readall.TotalCount)
	assert.Equal(t, updateSiteRuleBody, *readall.Data[0].CreateSiteRuleBody)

	err = sc.DeleteSiteRuleByID(corp, site, createResp.ID)
	if err != nil {
		t.Fatal(err)
	}
}

func TestUnMarshalListData(t *testing.T) {
	resp := []byte(`{
		"totalCount": 1,
		"data": [
		  {
			"id": "5e84ec28bf612801c7f0f109",
			"siteNames": [
			  "splunk-test"
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
			"createdBy": "janitha.jayaweera@gmail.com",
			"created": "2020-04-01T19:31:52Z",
			"updated": "2020-04-01T19:31:52Z"
		  }
		]
	  }`)

	var responseRulesList ResponseSiteRuleBodyList
	err := json.Unmarshal(resp, &responseRulesList)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 1, responseRulesList.TotalCount)
	assert.Equal(t, 1, len(responseRulesList.Data))
	assert.Equal(t, "5e84ec28bf612801c7f0f109", responseRulesList.Data[0].ID)
}

func TestDeleteAllSiteRules(t *testing.T) {
	t.SkipNow()
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := "splunk-tescorp"
	site := "splunk-test"
	respList, err := sc.GetAllSiteRules(corp, site)
	if err != nil {
		t.Fatal(err)
	}
	// assert.Equal(t, 0, len(respList))
	for _, rule := range respList.Data {
		sc.DeleteSiteRuleByID(corp, site, rule.ID)
	}
	respList, err = sc.GetAllSiteRules(corp, site)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 0, len(respList.Data))
}

func TestCreateReadUpdateDeleteSiteList(t *testing.T) {
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := "splunk-tescorp"
	site := "splunk-test"
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
	assert.Equal(t, createSiteListBody, *createresp.CreateListBody)

	readresp, err := sc.GetSiteListByID(corp, site, createresp.ID)
	assert.Equal(t, createSiteListBody, *readresp.CreateListBody)

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
	assert.NotEqual(t, createSiteListBody, *updateresp.CreateListBody)
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
	assert.Equal(t, updatedSiteListBody, *updateresp.CreateListBody)
	readall, err := sc.GetAllSiteLists(corp, site)
	assert.Equal(t, 1, len(readall.Data))
	assert.Equal(t, updatedSiteListBody, *readall.Data[0].CreateListBody)
	err = sc.DeleteSiteListByID(corp, site, readresp.ID)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCreateMultipleRedactions(t *testing.T) {
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := "splunk-tescorp"
	site := "splunk-test"

	createSiteRedactionBody := CreateSiteRedactionBody{
		Field:         "privatefield",
		RedactionType: 2,
	}
	createresp, err := sc.CreateSiteRedaction(corp, site, createSiteRedactionBody)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, createSiteRedactionBody, *createresp.CreateSiteRedactionBody)

	createSiteRedactionBody2 := CreateSiteRedactionBody{
		Field:         "cookie",
		RedactionType: 2,
	}
	createresp2, err := sc.CreateSiteRedaction(corp, site, createSiteRedactionBody2)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, createSiteRedactionBody2, *createresp2.CreateSiteRedactionBody)

	createSiteRedactionBody3 := CreateSiteRedactionBody{
		Field:         "cookie",
		RedactionType: 0,
	}
	createresp3, err := sc.CreateSiteRedaction(corp, site, createSiteRedactionBody3)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, createSiteRedactionBody3, *createresp3.CreateSiteRedactionBody)

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
func TestCreatListUpdateDeleteRedaction(t *testing.T) {
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := "splunk-tescorp"
	site := "splunk-test"

	createSiteRedactionBody := CreateSiteRedactionBody{
		Field:         "privatefield",
		RedactionType: 2,
	}
	createresp, err := sc.CreateSiteRedaction(corp, site, createSiteRedactionBody)

	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, createSiteRedactionBody, *createresp.CreateSiteRedactionBody)

	readresp, err := sc.GetSiteRedactionByID(corp, site, createresp.ID)
	assert.Equal(t, createSiteRedactionBody, *readresp.CreateSiteRedactionBody)

	updateSiteRedactionBody := CreateSiteRedactionBody{
		Field:         "cookie",
		RedactionType: 0,
	}
	updatedresp, err := sc.UpdateSiteRedactionByID(corp, site, createresp.ID, updateSiteRedactionBody)
	if err != nil {
		t.Fatal(err)
	}
	assert.NotEqual(t, createSiteRedactionBody, *updatedresp.CreateSiteRedactionBody)
	assert.Equal(t, updateSiteRedactionBody, *updatedresp.CreateSiteRedactionBody)
	readall, err := sc.GetAllSiteRedactions(corp, site)
	assert.Equal(t, 1, len(readall.Data))
	// assert.Equal(t, 1, readall.TotalCount)
	assert.Equal(t, updateSiteRedactionBody, *readall.Data[0].CreateSiteRedactionBody)
	err = sc.DeleteSiteRedactionByID(corp, site, createresp.ID)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSiteCreateReadUpdateDeleteAlerts(t *testing.T) {
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := "splunk-tescorp"
	site := "splunk-test"

	createCustomAlert := CustomAlertBody{
		TagName:   "SQLI",
		LongName:  "Example Alert",
		Interval:  1,
		Threshold: 10,
		Enabled:   true,
		Action:    "flagged",
	}
	createresp, err := sc.CreateCustomAlert(corp, site, createCustomAlert)
	// t.Logf("%#v", createresp.Data)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, createCustomAlert, *createresp.CustomAlertBody)
	readresp, err := sc.GetCustomAlert(corp, site, createresp.ID)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, createCustomAlert, *readresp.CustomAlertBody)

	updateCustomAlert := CustomAlertBody{
		TagName:   "SQLI",
		LongName:  "Example Alert Updated",
		Interval:  10,
		Threshold: 10,
		Enabled:   true,
		Action:    "flagged",
	}
	updateresp, err := sc.UpdateCustomAlert(corp, site, readresp.ID, updateCustomAlert)
	if err != nil {
		t.Fatal(err)
	}
	// t.Logf("%#v", updateresp)
	assert.NotEqual(t, createCustomAlert, *updateresp.CustomAlertBody)
	assert.Equal(t, updateCustomAlert, *updateresp.CustomAlertBody)

	err = sc.DeleteCustomAlert(corp, site, createresp.ID)
	if err != nil {
		t.Fatal(err)
	}
}
func TestCreateReadUpdateDeleteCorpRule(t *testing.T) {
	createCorpRuleBody := CreateCorpRuleBody{
		SiteNames:     []string{"splunk-test"},
		Type:          "signal",
		GroupOperator: "all",
		Conditions: []Condition{
			Condition{
				Type:     "single",
				Field:    "ip",
				Operator: "equals",
				Value:    "1.2.3.4",
			},
			Condition{
				Type:          "group",
				GroupOperator: "any",
				Conditions: []Condition{
					Condition{
						Type:     "single",
						Field:    "ip",
						Operator: "equals",
						Value:    "5.6.7.8",
					},
				},
			},
		},
		Actions: []Action{
			Action{
				Type: "excludeSignal",
			},
		},
		Enabled:    true,
		Reason:     "test",
		Signal:     "SQLI",
		Expiration: "",
		CorpScope:  "specificSites",
	}
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := "splunk-tescorp"
	createResp, err := sc.CreateCorpRule(corp, createCorpRuleBody)
	if err != nil {
		t.Fatal(err)
	}
	// t.Logf("%#v", createResp.CreateCorpRuleBody)
	assert.Equal(t, createCorpRuleBody, *createResp.CreateCorpRuleBody)

	readResp, err := sc.GetCorpRuleByID(corp, createResp.ID)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, readResp, createResp)
	updateCorpRuleBody := CreateCorpRuleBody{
		SiteNames:     []string{"splunk-test"},
		Type:          "signal",
		GroupOperator: "all",
		Conditions: []Condition{
			Condition{
				Type:     "single",
				Field:    "ip",
				Operator: "equals",
				Value:    "5.6.7.8",
			},
			Condition{
				Type:          "group",
				GroupOperator: "any",
				Conditions: []Condition{
					Condition{
						Type:     "single",
						Field:    "ip",
						Operator: "equals",
						Value:    "6.7.8.9",
					},
				},
			},
		},
		Actions: []Action{
			Action{
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
	assert.Equal(t, updateCorpRuleBody, *updateResp.CreateCorpRuleBody)
	readall, err := sc.GetAllCorpRules(corp)
	assert.Equal(t, 1, len(readall.Data))
	assert.Equal(t, 1, readall.TotalCount)
	assert.Equal(t, updateCorpRuleBody, *readall.Data[0].CreateCorpRuleBody)
	err = sc.DeleteCorpRuleByID(corp, createResp.ID)

	if err != nil {
		t.Fatal(err)
	}
}

func TestCreateReadUpdateDeleteCorpList(t *testing.T) {
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := "splunk-tescorp"
	createCorpListBody := CreateListBody{
		Name:        "My new list",
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
	assert.Equal(t, createCorpListBody, *createresp.CreateListBody)

	readresp, err := sc.GetCorpListByID(corp, createresp.ID)
	assert.Equal(t, createCorpListBody, *readresp.CreateListBody)

	updateCorpListBody := UpdateListBody{
		Description: "Some IPs we are updating in the list",
		Entries: Entries{
			Additions: []string{"3.4.5.6"},
			Deletions: []string{"4.5.6.7"},
		},
	}
	updateresp, err := sc.UpdateCorpListByID(corp, readresp.ID, updateCorpListBody)
	if err != nil {
		t.Fatal(err)
	}
	assert.NotEqual(t, createCorpListBody, *updateresp.CreateListBody)
	updatedCorpListBody := CreateListBody{
		Name:        "My new list",
		Type:        "ip",
		Description: "Some IPs we are updating in the list",
		Entries: []string{
			"2.3.4.5",
			"1.2.3.4",
			"3.4.5.6",
		},
	}
	assert.Equal(t, updatedCorpListBody, *updateresp.CreateListBody)
	readall, err := sc.GetAllCorpLists(corp)
	assert.Equal(t, 1, len(readall.Data))
	assert.Equal(t, updatedCorpListBody, *readall.Data[0].CreateListBody)
	err = sc.DeleteCorpListByID(corp, readresp.ID)
	if err != nil {
		t.Fatal(err)
	}
}
