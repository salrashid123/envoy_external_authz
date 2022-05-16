
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

For this we will use an easy jwt generator from Istio:

```bash
wget --no-verbose https://raw.githubusercontent.com/istio/istio/release-1.10/security/tools/jwt/samples/gen-jwt.py
wget --no-verbose https://raw.githubusercontent.com/istio/istio/release-1.10/security/tools/jwt/samples/key.pem

## for ref, the JWK URI = "https://raw.githubusercontent.com/istio/istio/release-1.10/security/tools/jwt/samples/jwks.json";
```

To generate a jwt with a prescribed role:

```bash
python3 gen-jwt.py -iss foo.bar -aud bar.bar -sub alice  -claims role:guest -expire 100000 key.pem                
```


```json
{
  "alg": "RS256",
  "kid": "DHFbpoIUqrY8t2zpA2qXfCmr5VO5ZEr4RzHU_-envvQ",
  "typ": "JWT"
}
{
  "aud": "bar.bar",
  "exp": 1652826027,
  "iat": 1652726027,
  "iss": "foo.bar",
  "role": "guest",
  "sub": "bob"
}
```

```bash
export GUEST_TOKEN=""

curl -v -H "Authorization: Bearer $GUEST_TOKEN" http://localhost:8080/get
```

### Run as admin


```bash
python3 gen-jwt.py -iss foo.bar -aud bar.bar -sub bob -claims role:admin -expire 100000 key.pem                
```

```json

```

```bash
export ADMIN_TOKEN="eyJhbGciOiJSUzI1NiIsImtpZCI6IkRIRmJwb0lVcXJZOHQyenBBMnFYZkNtcjVWTzVaRXI0UnpIVV8tZW52dlEiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJiYXIuYmFyIiwiZXhwIjoxNjUyODI1NDY5LCJpYXQiOjE2NTI3MjU0NjksImlzcyI6ImZvby5iYXIiLCJyb2xlIjoiYWRtaW4iLCJzdWIiOiJib2IifQ.d9Gt8O559t4OP4ZJOBFfeUIkHS0vUYlgB8ww7RlwvMUgvXBnD8n8pXGcfb2-7ei_Oby7qHgfoVM20F9EO9xC8tG0JV4IU8JfYJOlNzpzCHp8axrYv1h2yymZ6PRuH0V-rW96yFp_LG4fDicOxWK3EOjGCifNO5ID42KqttaiVtySr0hoaO37mV2nHWpjVa_RrcywGd0IeLWEFoWgO6gbwZPmV5gk5sH5oSsw2quLaRaVZgLaJRpzh6mjTeXYiKQsIGhYnaDpbdOZh4n0MSE1fLxiYSm1s2PK0kERlnPyhEQ3bBE24WlBmhImhtJNhG7oRb_IDCC-LFf72XlVAFfSoA"


curl -v -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost:8080/get
```


```json
{
  "alg": "RS256",
  "kid": "DHFbpoIUqrY8t2zpA2qXfCmr5VO5ZEr4RzHU_-envvQ",
  "typ": "JWT"
}
{
  "aud": "bar.bar",
  "exp": 1652825469,
  "iat": 1652725469,
  "iss": "foo.bar",
  "role": "admin",
  "sub": "bob"
}
```
