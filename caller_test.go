package govh

import "testing"

var caller *Caller

func TestNewCaller(t *testing.T) {
	var err error
	caller, err = NewCaller("ovh-eu", "INSERT AK", "INSERT AS", "")

	if err != nil {
		t.Fatal(err)
	}

	t.Log(caller.delay)
}

func TestPing(t *testing.T) {
	if err := caller.Ping(); err != nil {
		t.Fatal(err)
	}
}

func TestGetConsumerKey(t *testing.T) {
	ck, err := caller.GetConsumerKey(&GetCKParams{
		AccessRules: []*AccessRule{
			&AccessRule{
				Method: "GET",
				Path:   "/me",
			},
		},
	})

	if err != nil {
		t.Fatal(err)
	}

	t.Log(ck.ValidationUrl, ck.ConsumerKey)
}

func TestCallApi(t *testing.T) {
	caller.ConsumerKey = "INSERT VALIDATED CK"

	type Me struct {
		Name      string
		Firstname string
	}

	me := &Me{}

	err := caller.CallApi("/me", "GET", nil, me)

	if err != nil {
		t.Fatal(err)
	}

	t.Log(me.Firstname, me.Name)
}
