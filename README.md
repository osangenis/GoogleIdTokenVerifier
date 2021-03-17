# GoogleIdTokenVerifier

This is a fork of https://github.com/GoogleIdTokenVerifier/GoogleIdTokenVerifier to make the project production ready:
  - Manage all of the error scenarios verifying a non-trustable certificate
  - Loading Google certificates from https://www.googleapis.com/oauth2/v3/certs while using `cache-expiry`
  - Create unit tests of the different parts of the solution
  - Create integration tests (cert downloading)

This library is helpful when you're writing a Go service for dealing with user authentications. You can take advantage of Golang performance to validate the Google Authentication token from a Google sign-in, extract the profile data and manage your own users.

## Usage
To validate an Google ID Token in Golang


```
authToken := "XXXXXXXXXXX.XXXXXXXXXXXX.XXXXXXXXXX"

aud := "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.apps.googleusercontent.com"

fmt.Println(Verify(authToken, aud))
```

