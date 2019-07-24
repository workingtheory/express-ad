# Microsoft Active Directory Authentication Module for Express-based node apps

## Setup

1. First install this package in your electrode app

    ```
    yarn add @jet.com/express-ad
    ```

2. Add the following in your express app's `/config` folder. Make sure to import the express-ad module:

    ```
    {
        "authentication": {
            "module": "express-ad",
            "options: { 
                "host": XXX,
                "clientID": YYY,
                "clientSecret": ZZZ
            }
        }
    }
    ```
    
*Note that **host**, **clientID** and **clientSecret** are required properties. See the end of this document for a list of other optional properties and their default values.*

3. In your `/src/server/express-server.js` file, add the following helper method to inject authentication into the express pipeline:
```
const setUpAuth = () => new Promise((resolve, reject) => {
    const authModule = require((defaultConfig.$("authentication.module")));
    const authConfig = defaultConfig.$("authentication.options");
    const authDisabled = defaultConfig.$('authentication.disabled') || false;

    if (!authDisabled) {
        const authSetup = authModule(authConfig);
        app.use(authSetup);
    }
    resolve();
});
```
and then in the express server function, add `then(setUpAuth)` right before the setRouteHandler call: 
```
    .then(setStaticPaths)
    .then(setUpAuth)
    .then(setRouteHandler)
```

## Authentication flow

### On page load
When user opens a page that falls under protected path mask, the module will check if user is authenticated. If so, the page will open as intended. Otherwise, the user will be redirected to `'https://login.microsoftonline.com'` website in order to sign into the application. After signing in the user will be redirected to the configured `redirectUrlPath`. 

### On ajax call (e.g. API call)
If user is not authenticated at the time of request and `refresh_token` was never obtained before, the module will return `401` with `Location` header set to login page url. Otherwise the module will check if `access_token` was not expired. If it was expired, then the module will obtain a new one using the existing `refresh token` (which is valid for 90 days) and pass it to the api. The user won't notice anything except a small lag due to an additional request being made to `https://login.microsoftonline.com`. Once the `access_token` is renewed, all API calls will go through until it's expired again.

### Cookie storage 
The module stores both `access_token` and `refresh_token` in cookies, on user's machine. Both of these tokens are encrypted before being sent to the client. On each request to server the module will decrypt these cookies. Decryption affect each request and takes around 20 microseconds on a Quad Core 2.8 GHz Intel Core i7. Encryption affects token refreshes and in average takes around few hundreds microseconds on the same CPU.

## Configuration Properties

### `protectedPath`

The path to be protected by authentication module. 

Default: `/*`

### `clientID`

**Required.** The client ID of your application in AAD (Azure Active Directory)

---

### `host`

**Required.** Must be a https url string, unless you set allowHttpForRedirectUrl to true (which it is by default). Production environments should always use https for redirectUrl.

---

### `clientSecret` 

**Required.** The application secret that you created in the app registration portal for your app.

---

### `timeToRenewBeforeExpiration` 

Tells the module when `access_token` should be considered expired. This value will be substracted from the token's `expires_in` property returned from Azure AD. Basically, it allows to consider the token as expired some time in advance before it will expire on Azure.

Default: `600000  // 10 minutes`

---

### `refreshTokenAge`

Specifies lifetime of `refresh_token`.

Default: `7776000000 // 90 days`

---

### `identityMetadata`

The metadata endpoint provided by the Microsoft Identity Portal
that provides the keys and other important information at runtime

Default: `'https://login.microsoftonline.com/jetecommerce.onmicrosoft.com/.well-known/openid-configuration'`

---
  
### `responseType`

Must be `'code'`, `'code id_token'`, `'id_token code'` or `'id_token'`.
For login only flows you can use `'id_token'`; if you want access_token,
use `'code'`, `'code id_token'` or `'id_token code'`.

Default: `'id_token'`

---

### `responseMode`

Must be `'query'` or `'form_post'`. This is how you get code or id_token back. `'form_post'` is recommended for all scenarios.

Default: `'form_post'`

---

### `redirectUrlPath`

This is the reply URL path registered in AAD for your app.

Default: `'/auth/openid/return'`

---

### `allowHttpForRedirectUrl`

Required to set to true if you want to use http url for redirectUrl like http://localhost:3000

  Default: `true`

---

### `passReqToCallback`

Whether you want to use req as the first parameter in the verify callback.

Default: `false`

---

### `nonceLifetime`

State/nonce cookie expiration in seconds

Default: `600`

---

### `nonceMaxAmount`

Max amount of state/nonce cookie you want to keep (cookie is deleted after validation so this can be very small)

Default: `5`

---

### `useCookieInsteadOfSession`

Use cookie, not session

Default: `true`

---

### `cookieEncryptionKeys`

Encrypt/decrypt key and iv. Please manually set your `cookieEncryptionKeys` in setting.js. We recommend that you implement a secure secrets management tool such as [hashicorp](https://www.vaultproject.io/) vault instead of hardcoding security values or other secrets in your configuration files.

Default: `[ { key: '', 'iv': '' }]`

---

### `secret`

The secret used to sign the JWTs and the cookies that hold them

Default: `'Going down to queso town'`

---

### `timeToRenewBeforeExpiration`

Time in ms before expiration to renew the JWT.

Default: `1e3 * 60 * 10` - 10 minutes



