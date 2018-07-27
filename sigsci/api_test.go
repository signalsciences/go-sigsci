package sigsci

import (
	"log"
)

func ExampleClient_InviteUser() {
	email := "[email]"
	password := "[password]"
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
