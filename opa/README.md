
## OPA External Authz


Just a repro of the docs for [OpenPolicy Agent](https://github.com/open-policy-agent/opa-envoy-plugin) for Envoy

see 


[Envoy External Authorization with OPA](https://blog.openpolicyagent.org/envoy-external-authorization-with-opa-578213ed567c)


  >>> *NOTE*:  this repo uses `envoy 1.17`

```
docker cp `docker create envoyproxy/envoy-dev:latest`:/usr/local/bin/envoy .
```

To use my example

#### Run OPA

```bash
docker run -p 8181:8181 -p 9191:9191 -v `pwd`/opa_policy:/policy -v `pwd`/opa_config:/config openpolicyagent/opa:latest-envoy run   --server --addr=localhost:8181 --set=plugins.envoy_ext_authz_grpc.addr=:9191 --set=decision_logs.console=true --ignore=.* /policy/policy.rego
```

the specific rego policy here decodes the inbound JWT (which uses the HS password `secret`), then extracts the sub field to match rules later on

```
package envoy.authz

import input.attributes.request.http as http_request

default allow = false

token = {"valid": valid, "payload": payload} {
    [_, encoded] := split(http_request.headers.authorization, " ")
    [valid, _, payload] := io.jwt.decode_verify(encoded, {"secret": "secret"})
}

allow {
    is_token_valid
    action_allowed
}

is_token_valid {
  token.valid
  token.payload.nbf <= time.now_ns() < token.payload.exp
}

action_denied {
  http_request.method == "GET"
  token.payload.role == "guest"
  glob.match("/get*", [], http_request.path)
}

action_allowed {
  http_request.method == "GET"
  token.payload.role == "admin"
  glob.match("/get*", [], http_request.path)
}

action_allowed {
  http_request.method == "POST"
  token.payload.role == "admin"
  glob.match("/post", [], http_request.path)
  lower(input.parsed_body.firstname) != base64url.decode(token.payload.sub)
}
```

#### Run as guest

```json
{
  "role": "guest",
  "sub": "YWxpY2U=",
  "nbf": 1514851139,
  "exp": 1641081539
}
```

```bash
export GUEST_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiZ3Vlc3QiLCJzdWIiOiJZV3hwWTJVPSIsIm5iZiI6MTUxNDg1MTEzOSwiZXhwIjoxNjQxMDgxNTM5fQ.K5DnnbbIOspRbpCr2IKXE9cPVatGOCBrBQobQmBmaeU"

curl -v -H "Authorization: Bearer $GUEST_TOKEN" http://localhost:8080/get
```

### Run as admin

```json
{
  "role": "admin",
  "sub": "Ym9i",
  "nbf": 1514851139,
  "exp": 1641081539
}
```

```bash
export ADMIN_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4iLCJzdWIiOiJZbTlpIiwibmJmIjoxNTE0ODUxMTM5LCJleHAiOjE2NDEwODE1Mzl9.WCxNAveAVAdRCmkpIObOTaSd0AJRECY2Ch2Qdic3kU8"


curl -v -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost:8080/get
```