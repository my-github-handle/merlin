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
)

func TestDockerTokenHandshake(t *testing.T) {
	iss := auth.NewRegistryTokenIssuer([]byte("s"), "merlin", time.Minute)
	h := NewHandler(fakeAuth{ok: true}, nil, nil, nil, "myreg.azurecr.io", nil)
	h.SetRegistryAuth(iss, "", "merlin") // realm filled below via server URL
	th := &TokenHandler{Authn: stubAuthn{ok: true}, ClientCreds: stubClientCreds{ok: false}, Issuer: iss}
	h.SetTokenHandler(th)

	srv := httptest.NewServer(h)
	defer srv.Close()

	// 1. unauthenticated /v2/ -> 401 with a Bearer challenge
	resp, _ := http.Get(srv.URL + "/v2/")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/v2/ unauth code = %d", resp.StatusCode)
	}
	// 2. fetch a token from /token with the Entra user token as Basic password
	tokReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/token?service=merlin&scope=repository:app:push,pull", nil)
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
