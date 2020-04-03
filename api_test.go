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
func TestCreateSite(t *testing.T) {
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := "splunk-testcorp"

	siteBody := CreateSiteBody{
		Name:                 "janitha-test-site",
		DisplayName:          "Janitha Test Site",
		AgentLevel:           "Log",
		BlockHTTPCode:        406,
		BlockDurationSeconds: 86400,
		AgentAnonMode:        "off",
	}
	_, err := sc.CreateSite(corp, siteBody)
	if err == nil {
		t.Fatal("Can create more than one site. Clean up not implemented")
	}
	assert.Equal(t, "Site limit reached", err.Error())

}
func TestDeleteSite(t *testing.T) {
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := "splunk-testcorp"
	site := "janitha-test-site" //do not have permission at the moment anyway
	err := sc.DeleteSite(corp, site)
	if err == nil {
		t.Fatalf("This site %s should not exist", site)
	}
	assert.Equal(t, "Site not found", err.Error())
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
	t.SkipNow()
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
	testCases := map[string]map[string]func(t *testing.T){
		"Site": {
			"create": TestCreateSite,
			"delete": TestDeleteSite,
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
