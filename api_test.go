package sigsci

import (
	"encoding/json"
	"log"
	"os"
	"reflect"
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

func TestCreateSiteRules(t *testing.T) {

	siteRulesBody := CreateSiteRulesBody{
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
	rules, err := sc.CreateSiteRules(corp, site, siteRulesBody)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, siteRulesBody, *rules.CreateSiteRulesBody)
	err = sc.DeleteSiteRule(corp, site, rules.ID)
	if err != nil {
		t.Fatal(err)
	}
}
func TestUpdateSiteRules(t *testing.T) {

	siteRulesBody := CreateSiteRulesBody{
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
	rule, err := sc.CreateSiteRules(corp, site, siteRulesBody)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, siteRulesBody, *rule.CreateSiteRulesBody)

	siteUpdatedBody := CreateSiteRulesBody{
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
	updatedRule, err := sc.UpdateSiteRule(corp, site, *&rule.ID, siteUpdatedBody)
	assert.Equal(t, siteUpdatedBody, *updatedRule.CreateSiteRulesBody)
	err = sc.DeleteSiteRule(corp, site, rule.ID)
	if err != nil {
		t.Fatal(err)
	}
}
func TestListSiteRules(t *testing.T) {
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := "splunk-tescorp"
	site := "splunk-test"
	_, err := sc.ListSiteRules(corp, site)
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

	var responseRulesList ResponseSiteRulesListData
	err := json.Unmarshal(resp, &responseRulesList)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 1, responseRulesList.TotalCount)
	assert.Equal(t, 1, len(responseRulesList.Data))
	assert.Equal(t, "5e84ec28bf612801c7f0f109", responseRulesList.Data[0].ID)
}

func TestDeleteAllSiteRules(t *testing.T) {
	// t.SkipNow()
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := "splunk-tescorp"
	site := "splunk-test"
	respList, err := sc.ListSiteRules(corp, site)
	if err != nil {
		t.Fatal(err)
	}
	// assert.Equal(t, 0, len(respList))
	for _, rule := range respList {
		sc.DeleteSiteRule(corp, site, rule.ID)
	}
	respList, err = sc.ListSiteRules(corp, site)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 0, len(respList))
}

func TestGetSiteRuleById(t *testing.T) {
	siteRulesBody := CreateSiteRulesBody{
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
	rule, err := sc.CreateSiteRules(corp, site, siteRulesBody)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, siteRulesBody, *rule.CreateSiteRulesBody)

	readRule, err := sc.GetSiteRuleById(corp, site, *&rule.ID)

	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, siteRulesBody, *readRule.CreateSiteRulesBody)

	err = sc.DeleteSiteRule(corp, site, rule.ID)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSigSciAPI(t *testing.T) {
	t.SkipNow()
	testCases := map[string]map[string]func(t *testing.T){
		"Site": {
			"createdelete": TestCreateDeleteSite,
		},
		"Rule": {
			"list":               TestListSiteRules,
			"createdelete":       TestCreateSiteRules,
			"createreaddelete":   TestGetSiteRuleById,
			"createupdatedelete": TestUpdateSiteRules,
			"delete":             TestDeleteAllSiteRules,
		},
	}
	for group, m := range testCases {
		m := m
		t.Run(group, func(t *testing.T) {
			for name, tc := range m {
				tc := tc
				t.Run(name, func(t *testing.T) {
					tc(t)
				})
			}
		})
	}
}

func TestCreateReadUpdateDeleteSiteList(t *testing.T) {
	testCases := []struct {
		createFunc     func(string, string, CreateSiteListBody) (ResponseSiteListBody, error)
		deleteFunc     func(string, string, string) error
		createBody     interface{}
		createBodyType string
	}{
		{
			NewTokenClient(testcreds.email, testcreds.token).CreateSiteList, //this is method I think these works for functions
			NewTokenClient(testcreds.email, testcreds.token).DeleteSiteListByID,
			CreateSiteListBody{
				Name:        "My new List",
				Type:        "ip",
				Description: "Some IPs we are putting in a list",
				Entries: []string{
					"4.5.6.7",
					"2.3.4.5",
					"1.2.3.4",
				},
			},
			"CreateSiteListBody",
		},
	}
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := "splunk-tescorp"
	site := "splunk-test"

	// createresp, err := sc.CreateSiteList(corp, site, siteListBody)
	mytype := reflect.TypeOf(testCases[0].createBody)
	// myval := reflect.ValueOf(testCases[0].createBody)

	// t.Logf("%v, %v", mytype, myval)
	assert.Equal(t, mytype, reflect.TypeOf(CreateSiteListBody{}))
	createresp, err := testCases[0].createFunc(corp, site, testCases[0].createBody.(CreateSiteListBody))
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, testCases[0].createBody.(CreateSiteListBody), *createresp.CreateSiteListBody)
	readresp, err := sc.GetSiteListByID(corp, site, createresp.ID)
	assert.Equal(t, testCases[0].createBody.(CreateSiteListBody), *readresp.CreateSiteListBody)

	updateSiteListBody := UpdateSiteListBody{
		Description: "Some IPs we are updating in the list",
		Entries: Entries{
			Additions: []string{"3.4.5.6"},
			Deletions: []string{"4.5.6.7"},
		},
	}
	updatedresp, err := sc.UpdateSiteListByID(corp, site, readresp.ID, updateSiteListBody)
	if err != nil {
		t.Fatal(err)
	}
	assert.NotEqual(t, testCases[0].createBody.(CreateSiteListBody), *updatedresp.CreateSiteListBody)
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
		RedactionType: 1,
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

	listresp, err := sc.ListSiteRedactions(corp, site)
	assert.Equal(t, 1, len(listresp.Data))

	readresp, err := sc.GetSiteRedactionByID(corp, site, createresp.ID)
	assert.Equal(t, createSiteRedactionBody, *readresp.CreateSiteRedactionBody)

	updateSiteRedactionBody := UpdateSiteRedactionBody{
		Field:         "cookie",
		RedactionType: 1,
	}
	updatedresp, err := sc.UpdateSiteRedactionByID(corp, site, createresp.ID, updateSiteRedactionBody)
	if err != nil {
		t.Fatal(err)
	}

	assert.NotEqual(t, createSiteRedactionBody, *updatedresp.CreateSiteRedactionBody)
	assert.Equal(t, updateSiteRedactionBody.Field, *&updatedresp.CreateSiteRedactionBody.Field)
	assert.Equal(t, updateSiteRedactionBody.RedactionType, *&updatedresp.CreateSiteRedactionBody.RedactionType)

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
