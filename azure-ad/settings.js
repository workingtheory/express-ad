const merge = require("lodash").merge;

const defaultSettings = {

    //----------------------------------------------
    // ** OIDCStrategy Option Configs ** //
    //----------------------------------------------

    // The metadata endpoint provided by the Microsoft Identity Portal
    // that provides the keys and other important information at runtime
    identityMetadata: 'https://login.microsoftonline.com/jetecommerce.onmicrosoft.com/.well-known/openid-configuration',

    // The client ID of your application in AAD (Azure Active Directory)
    // const clientID = clientConfig.authorization.clientId;

    // Must be 'code', 'code id_token', 'id_token code' or 'id_token'.
    // For login only flows you can use 'id_token'; if you want access_token,
    // use 'code', 'code id_token' or 'id_token code'.
    responseType: 'code id_token',

    // Must be 'query' or 'form_post'. This is how you get code or id_token back.
    // 'form_post' is recommended for all scenarios.
    responseMode: 'form_post',

    host: 'http://localhost',

    // Must be a https url string, unless you set allowHttpForRedirectUrl to true.
    // This is the reply URL registered in AAD for your app. Production environment
    // should always use https for redirectUrl.
    redirectUrlPath: '/auth/openid/return',
    // const redirectUrl = clientConfig.host + redirectUrlPath;

    // Required to set to true if you want to use http url for redirectUrl like http://localhost:3000
    allowHttpForRedirectUrl: true,

    // Whether you want to use req as the first parameter in the verify callback.
    passReqToCallback: true,

    // State/nonce cookie expiration in seconds
    nonceLifetime: 600,

    // Max amount of state/nonce cookie you want to keep (cookie is deleted after validation so this can be very small)
    nonceMaxAmount: 5,

    // Use cookie, not session
    useCookieInsteadOfSession: true,

    // Encrypt/decrypt key and iv
    cookieEncryptionKeys: [{ key: '', 'iv': '' }],

    //----------------------------------------------
    // ** Other Configs ** //
    //----------------------------------------------

    // The secret used to sign the JWTs and the cookies that hold them
    secret: 'This is a big secret',

    // Cookie lifespan in milliseconds
    cookieAge: 1800000,

    // renew the token Nms before it expires
    timeToRenewBeforeExpiration: 1e3 * 60 * 10,

    // azure ad refresh token lifetime
    refreshTokenAge: 90 * 24 * 60 * 60 * 1e3
}

// Other possible options to be used with OIDCStrategy can be found in the docs at
// https://github.com/AzureAD/passport-azure-ad

module.exports = function (clientSettings) {

    let config = merge({}, defaultSettings, clientSettings);

    return {
        oidc: {
            identityMetadata: config.identityMetadata,
            clientID: config.clientID,
            responseType: config.responseType,
            responseMode: config.responseMode,
            redirectUrlPath: config.redirectUrlPath,
            redirectUrl: config.host + config.redirectUrlPath,
            allowHttpForRedirectUrl: config.allowHttpForRedirectUrl,
            passReqToCallback: config.passReqToCallback,
            nonceLifetime: config.nonceLifetime,
            nonceMaxAmount: config.nonceMaxAmount,
            useCookieInsteadOfSession: config.useCookieInsteadOfSession,
            cookieEncryptionKeys: config.cookieEncryptionKeys,
            allowAllHosts: config.allowAllHosts,
            clientSecret: config.clientSecret,
            forceProtocol: config.forceProtocol
        },
        bearer: {
            identityMetadata: config.identityMetadata,
            clientID: config.clientID,
            passReqToCallback: config.passReqToCallback,
            timeToRenewBeforeExpiration: config.timeToRenewBeforeExpiration
        },
        cookie: {
            secret: config.secret,
            cookieAge: config.cookieAge,
            refreshTokenAge: config.refreshTokenAge
        }
    }

}
