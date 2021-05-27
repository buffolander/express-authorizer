# Introduction

This package handles authentication and role-based auhtorization for JSON Web Tokens (JWTs) as middlewares on Express Servers.

# Usage

Get it up and running on your server with a single configuration file, in three easy steps:

1. Add your Authentication parameters
2. Add your Authorization parameters
3. Create your policies

```javascript
// file: gatekeeper.js, your configuration file
const { default: ExpressAuthorizer } = require('@brdu/express-authorizer')

const gatekeeper = new ExpressAuthorizer('EXPRESS')

gatekeeper.set_authentication_params(/* Authentication parameters */)

gatekeeper.set_authorization_params(/* Authorization parameters */)

gatekeeper.add_policy(/* Policy 1 */)
gatekeeper.add_policy(/* Policy 2 */)
/* ... */
gatekeeper.add_policy(/* Policy n */)

module.exports = gatekeeper
```

Import the configuration on your server file and apply the middlewares.

```javascript
// file: server.js
const express = require('express')
const gatekeeper = require('./gatekeeper')

const app = express()
app.use(gatekeeper.authenticate) // <==
app.use(gatekeeper.authorize) // <==

/* Declare your routes */
app.use('*', (req, res) => res.sendStatus(404))

const port = process.env.PORT || 8080
app.listen(port, () => console.info(`server listening on port ${port}`))
```

The ExpressAuthorizer constructor takes a single parameter to initialize a new instance.

It accepts either one of `EXPRESS` or `API_GATEWAY`.

When initialized with the value `EXPRESS`, your server you'll be responsible for authenticating each request.

You're required to set up athentication parameters on your configuration if you intend to use the `ExpressAuthorizer.authenticate` middleware on your server.

Initializing the ExpressAuthorizer instance with the value `API_GATEWAY` means the request has been previously authenticated by an API Gateway or another service.

Authentication parameters will be ignored if declared, and using `ExpressAuthorizer.authenticate` middleware on your server will throw an exception.

You may choose to use only `ExpressAuthorizer.authenticate` if authorization isn't required, as well as only use `ExpressAuthorizer.authorize` if requests have been previously authenticated before received by your server.

# Setting up Authentication Parameters

This method sets up all parameters required by the `ExpressAuthorizer.authenticate` middleware.

```javascript
gatekeeper.set_authentication_params({
  secret_type: 'PEM',
  secret: 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com',
  secret_refresh_interval: 5,
  audience: 'my-app',
  issuer: 'https://securetoken.google.com/my-app',
})
```

| AuthenticationParams properties |
| :--- |
| <br />**`secret_type`** (required, enum `PLAIN_TEXT`, `PEM`, `JWK`): The property specifies the type of secret available to verify the JWT sent with the request. |
| <br />**`secret`** (required): The property accepts multiple formats. (next) |
| <br />**`secret_refresh_interval`** (optional): Whenever your identity service uses key rotation for signing JWTs, you may specify the time interval (in minutes) those keys must be refreshed and ExpressAuthorizer will handle it in the background. |
| <br />**`audience`** (optional): When not declared, ExpressAuthorizer won't verify the `aud` claim from the request JWT. |
| <br />**`issuer`** (optional): When not declared, ExpressAuthorizer won't verify the `iss` claim from the request JWT. |
<br />

| `secret` accepted formats |
| :--- |
| <br />**String (format: url)**: When a url is passed as secret, ExpressAuthorizer will retrieve it when your server starts and pass the returned value to the JWT verifier. URLs are accepted for any `secret_type` value. |
| <br />**String (format: any)**: This secret format is only accepted when `service_type=PLAIN_TEXT`. |
| <br />**PEM Public Key(s)**: This secret format is only accepted when `service_type=PEM`. ExpressAuthorizer expects either a single PEM as a string or a JSON object with multiple PEMs where keys are each PEM **kid**. ([example](https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com)) |
| <br />**JWK or JWKS**: This secret format is only accepted when `service_type=JWK`. ExpressAuthorizer will retrieve the **kid** from the JWT header and build a PEM from your JWK. ([example](https://dev-45670431.okta.com/oauth2/v1/keys)) |
<br />

# Setting up Authorization Parameters

At the moment it's required all of the custom claims assigned to users to be nested under a root property. In the following example `users_claims_root_key` is *organizations*.

Users custom claims might be represented as a JSON object or as a collection (an array of objects).

Additionally, all claims in the organization object (`organization_group`, `organization_id`, `roles`) are required in your JWT. *On the next minor version this requirement will be dropped.*

```
{
  "organizations": [{
    "organization_group": "internal",
    "organization_id": "marketing",
    "roles": ["manager", "user"],
  }, {
    "organization_group": "internal",
    "organization_id": "global",
    "roles": ["user"],
  }],
  "iss": "https://securetoken.google.com/my-app",
  "aud": "my-app",
  "auth_time": 1620618241,
  "user_id": "Z0KuS5Hjn0UfBzW86p5zqGqBTIP2",
  "sub": "Z0KuS5Hjn0UfBzW86p5zqGqBTIP2",
  "iat": 1620618241,
  "exp": 1620621841,
  "email": "johndoe@example.com",
  "email_verified": true,
  "firebase": {
    "identities": {
      "email": ["johndoe@example.com"]
    },
    "sign_in_provider": "password"
  }
}
```

This method sets up all parameters required to map users' custom claims on JWTs. `ExpressAuthorizer.authorize` will work with the payload from the decoded JWT and your policies to determine users authority over any operation.

```javascript
gatekeeper.set_authorization_params({
  user_id_key: 'user_id',
  user_claims_root_key: 'organizations',
  organization_group_key: 'organization_group',
  organization_id_key: 'organization_id',
  user_roles_key: 'roles',
  // The next properties apply only when auth_agent=API_GATEWAY
  identity_context_header_key: 'X-Endpoint-API-UserInfo',
  identity_context_transformation_function: (value) => {
    let parsedContext
    try {
      const contextString = Buffer.from(value, 'base64').toString('utf-8')
      parsedContext = JSON.parse(contextString)
    } catch (err) {
      parsedContext = {}
    }
    return parsedContext
  },
})
```

| AuthorizationParams properties |
| :--- |
| <br />**`user_id_key`** (optional, default 'user_id'): It maps the user id key in your JWT. |
| <br />**`user_claims_root_key`** (optional, default 'organizations'): It maps the root key for your custom claims. Removing the requirement for a root to the custom claims object (or array) is in the project backlog. |
| <br />**`organization_group_key`** (optional, default 'organization_group'): It maps the key for organization groups in your JWT. It's currently required both in your authorization parameters, as well as in your policies. |
| <br />**`organization_id_key`** (optional, default 'organization_id'): It maps the organization id key in your JWT. |
| <br />**`user_roles_key`** (optional, default 'user_id'): It maps the key to the user roles array in your JWT. |
| <br />**`identity_context_header_key`** (optional, type String): In case your requests are authenticated by an API Gateway, when it's upstreamed to the internal service, the decoded JWT is usually passed on another header. |
| <br />**`identity_context_transformation_function`** (optional, type Function): Since request headers accept only strings - JSON objects can't be passed in the headers -, the function specified here will be responsible for hydrating the identity context back into a JSON object.  |
<br />
# Setting up Policies

Policies determine which users are allowed to consume your service operations. ExpressAuthorizer will extract relevant data from the JWT token, build the user roles and compare them against your policies to determine whether to deny acess (and return status code 403), or allow the request to reach your controllers.

ExpressAuthorizer assumes that routes not present in any policy are open to any authenticated request.

```javascript
gatekeeper.add_policy({
  operations: [{
    path: '/users/:id',
    methods: ['POST', 'PATCH'],
  }],
  authorized_roles: 'self',
  user_id_alt_key: 'id',
})

gatekeeper.add_policy({
  operations: [{
    path: '/companies/:company_id/banking-info',
    methods: ['GET', 'POST', 'PATCH'],
  }],
  authorized_roles: [{
    organization_group: 'customers',
    roles: ['admin', 'billing'],
  }],
  organization_id_alt_key: 'company_id',
  organization_restricted: true,
})
```

## Policy properties

| Policy properties |
| :--- |
| <br />**`operations`** (required): An API operation is the combination of a path and a method. You may specify mutiple operations that must adhere to the same policy, and declare multiple methods for a single path - as seen on the previous example. |
| <br />**`operations.path`** (required): The endpoint path in Express format. |
| <br />**`operations.methods`** (required): The methods included in the policy for each one of the paths declared. |
| <br />**`authorized_roles`** (required): This is a complex property that accepts as value either a string or an array of objects. The accepted string values are `'self'` and `'*'`; where `'self'` refers to only the authenticated user itself, and `'*'` refers to any authenticated user. |
| <br />**`authorized_roles.organization_group`** (required): It refers to the organization groups allowed to access those operations; e.g. on an accounting system, organization groups could be represented by `'customers'`, `'suppliers'`, and `'internal_staff'`. It also accepts `'*'` as a wildcard representing any organization group. |
| <br />**`authorized_roles.roles`** (required): It represents the authenticated user role(s) within an organization. This property accepts either an array of strings, as well as the wilcard `'*'` representing any role within an organization. |
| <br />**`user_id_alt_key`** (optional): When the declared `authorized_roles` is `'self'`, ExpressAuthorizer will look for a user_id in the path, then the request query string, and lastly in the request body. `user_id_alt_key` allows you to specify a key different from the one declared on `AuthorizationParams.user_id_key` |
| <br />**`organization_id_alt_key`** (optional): When the declared `authorized_roles` is an array of objects, ExpressAuthorizer will look for an organization_id in the path, then the request query string, and lastly in the request body. `organization_id_alt_key` allows you to specify a key different from the one declared on `AuthorizationParams.organization_id_key` |
| <br />**`organization_restricted`** (optional): The property tells ExpressAuthorizer whether or not to restrict resquests based on the organization_ids found on the JWT and the one found on the http request - either on its path, query string or the request body. |
<br />
