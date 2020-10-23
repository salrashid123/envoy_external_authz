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