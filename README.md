# Authorization helper

Integrates traefik ForwardAuth with a secure token exchange.

The requested audience for the new token is taken from the last URI segment.
The scopes are assumed to be configured in the client definition of the token
exchange.

