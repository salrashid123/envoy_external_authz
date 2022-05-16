package envoy.authz

import input.attributes.request.http as http_request

jwks = `{
  "keys": [
    {
      "e": "AQAB",
      "kid": "DHFbpoIUqrY8t2zpA2qXfCmr5VO5ZEr4RzHU_-envvQ",
      "kty": "RSA",
      "n": "xAE7eB6qugXyCAG3yhh7pkDkT65pHymX-P7KfIupjf59vsdo91bSP9C8H07pSAGQO1MV_xFj9VswgsCg4R6otmg5PV2He95lZdHtOcU5DXIg_pbhLdKXbi66GlVeK6ABZOUW3WYtnNHD-91gVuoeJT_DwtGGcp4ignkgXfkiEm4sw-4sfb4qdt5oLbyVpmW6x9cfa7vs2WTfURiCrBoUqgBo_-4WTiULmmHSGZHOjzwa8WtrtOQGsAFjIbno85jp6MnGGGZPYZbDAa_b3y5u-YpW7ypZrvD8BgtKVjgtQgZhLAGezMt0ua3DRrWnKqTZ0BJ_EyxOGuHJrLsn00fnMQ"
    }
  ]
}`

default allow = false

token = {"valid": valid, "payload": payload} {
    [_, jwt] := split(http_request.headers.authorization, " ")
    valid := io.jwt.verify_rs256(jwt, jwks)
    [_, payload, _] := io.jwt.decode(jwt) 
    payload.iss == "foo.bar"
}

allow {
    is_token_valid
    action_allowed
}

is_token_valid {
  token.valid
  token.payload.iat <= time.now_ns() < token.payload.exp
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