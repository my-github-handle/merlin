package docker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/auth"
	"github.com/merlin-gate/merlin/internal/tenant"
)

func TestDockerTokenHandshake(t *testing.T) {
	iss := auth.NewRegistryTokenIssuer([]byte("s"), "merlin", time.Minute)
	res := anyResolver{t: &tenant.Tenant{Prefix: "c3dev", Registry: "myreg.azurecr.io", Authn: stubAuthn{ok: true}}}
	// Unstarted, so the listener address — and therefore the realm the challenge will
	// advertise — is known before the handler is built. It used to be set to "", which
	// is what a real docker client cannot follow; New now rejects that, so the realm is
	// the true one and step 2 below follows it instead of reconstructing the URL.
	srv := httptest.NewUnstartedServer(nil)
	realm := "http://" + srv.Listener.Addr().String() + "/token"
	h := mustNewHandler(t, HandlerConfig{
		Resolver:       res,
		RegistryIssuer: iss,
		TokenRealm:     realm,
		Service:        "merlin",
		TokenHandler:   &TokenHandler{Resolver: res, ClientCreds: stubClientCreds{ok: false}, Issuer: iss},
	})
	srv.Config.Handler = h
	srv.Start()
	defer srv.Close()

	// 1. unauthenticated /v2/ -> 401 with a Bearer challenge
	resp, _ := http.Get(srv.URL + "/v2/")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/v2/ unauth code = %d", resp.StatusCode)
	}
	// The realm is the only thing telling the client where to go next, so follow it
	// rather than assuming it: a challenge that points somewhere unreachable stops the
	// push with no error anywhere in Merlin.
	if got, want := realmFromChallenge(resp.Header.Get("WWW-Authenticate")), realm; got != want {
		t.Fatalf("challenge realm = %q, want %q", got, want)
	}
	// 2. fetch a token from the advertised realm with the Entra user token as Basic password
	tokReq, _ := http.NewRequest(http.MethodGet, realm+"?service=merlin&scope=repository:app:push,pull", nil)
	tokReq.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("u:good-entra-token")))
	tokResp, err := http.DefaultClient.Do(tokReq)
	if err != nil || tokResp.StatusCode != http.StatusOK {
		t.Fatalf("/token code = %v err=%v", tokResp.StatusCode, err)
	}
	var body struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(tokResp.Body).Decode(&body)
	if body.Token == "" {
		t.Fatal("no token issued")
	}
	// 3. replay the registry token on /v2/ -> 200
	v2, _ := http.NewRequest(http.MethodGet, srv.URL+"/v2/", nil)
	v2.Header.Set("Authorization", "Bearer "+body.Token)
	v2resp, _ := http.DefaultClient.Do(v2)
	if v2resp.StatusCode != http.StatusOK {
		t.Errorf("replay registry token /v2/ code = %d, want 200", v2resp.StatusCode)
	}
	_ = context.Background
	_ = strings.TrimSpace
}

// realmFromChallenge pulls realm="..." out of a Bearer WWW-Authenticate header,
// returning "" if it is absent — which is exactly the failure New now prevents.
func realmFromChallenge(challenge string) string {
	for _, part := range strings.Split(strings.TrimPrefix(challenge, "Bearer "), ",") {
		if k, v, ok := strings.Cut(part, "="); ok && strings.TrimSpace(k) == "realm" {
			return strings.Trim(v, `"`)
		}
	}
	return ""
}
