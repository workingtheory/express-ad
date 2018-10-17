const passport = require('passport')
const crypto = require('crypto');
const request = require('request');

const cookieParser = {
  setCookie: (req, res, name, value, options) => {
    cookieParser.clearCookie(req, res, name);
    const chunks = (value || '').match(/.{1,4000}/g) || [];
    chunks.forEach((_, index) => {
      res.cookie(`${name}.${index}`, _, options);
    });
  },
  getCookie: (req, name) => {
    let i = 0,
      chunk,
      whole = '';

    while (chunk = req.signedCookies[`${name}.${i++}`]) {
      whole += chunk;
    }

    return whole || undefined;
  },
  clearCookie: (req, res, name) => {
    let i = 0;

    while (req.signedCookies[`${name}.${i}`]) {
      res.cookie(`${name}.${i}`, '', { expires: new Date() });
      i++;
    }
  }
};

// Export function for checking authentication
module.exports = (path = '', name = '', settings) => {
  const ALGO = 'aes-256-ctr';

  const clearCookies = (req, res) => {
    cookieParser.clearCookie(req, res, `${name}_atoken`);
    cookieParser.clearCookie(req, res, `${name}_rtoken`);
    cookieParser.clearCookie(req, res, `${name}_data`);
  }

  const encrypt = (data) => {
    if (!data) return data;
    const cipher = crypto.createCipher(ALGO, settings.oidc.clientSecret);
    let crypted = cipher.update(data, 'utf8', 'hex');
    crypted += cipher.final('hex');
    return crypted;
  };

  const decrypt = (data) => {
    if (!data) return data;
    const decipher = crypto.createDecipher(ALGO, settings.oidc.clientSecret);
    let dec = decipher.update(data, 'hex', 'utf8');
    dec += decipher.final('utf8');
    return dec;
  };

  const refreshToken = (refreshToken, req, res, next) => {
    request('https://login.microsoftonline.com/common/oauth2/token', {
      headers: {
        'Accept': 'application/json'
      },
      method: 'POST',
      formData: {
        grant_type: 'refresh_token',
        client_id: settings.oidc.clientID,
        refresh_token: refreshToken,
        resource: settings.oidc.clientID,
        client_secret: settings.oidc.clientSecret
      }
    }, (err, response, body) => {
      if (err) {
        return next();
      }
      try {
        const tokens = JSON.parse(body);
        if (tokens.error) {
          clearCookies(req, res);
          return res.redirect(`${path}/logout`);
        }
        giveToken(req, res, {
          params: {
            expires_in: tokens.expires_in
          },
          access_token: tokens.access_token,
          refresh_token: tokens.refresh_token
        });
        checkAuth(req, res, next, tokens);
      } catch (e) {
        next();
      }
    });
  };

  const patchResponse = (res) => {
    const set = res.set;
    res.set = (header, value) => {
      if (!res.headersSent) {
        if (header === 'set-cookie') {
          value = (res._headers['set-cookie'] || []).concat(value);
        }
        if (header === 'X-USER-DATA') {
          value = res.headers['X-USER-DATA'];
        }
      }
      set.apply(res, [header, value]);
    }
  };

  const checkAuth = (req, res, next, rawTokens = {}) => {
    const encryptedTokens = {
      access_token: cookieParser.getCookie(req, `${name}_atoken`),
      refresh_token: cookieParser.getCookie(req, `${name}_rtoken`)
    };
    const encryptedUserData = cookieParser.getCookie(req, `${name}_data`);

    process.env.DEBUG && console.time('tokens decryption');
    const decryptedTokens = {
      access_token: rawTokens.access_token || decrypt(encryptedTokens.access_token),
      refresh_token: rawTokens.refresh_token || decrypt(encryptedTokens.refresh_token)
    };
    const decryptedUserData = decrypt(encryptedUserData);
    process.env.DEBUG && console.timeEnd('tokens decryption');

    // if access_token expired then refresh it using a non-expired refresh token
    if (decryptedTokens.refresh_token && !decryptedTokens.access_token) {
      return refreshToken(decryptedTokens.refresh_token, req, res, next);
    }

    // if current request is an AJAX call then attach access token to it
    if (req.xhr || req.headers.accept.indexOf('json') > -1) {
      patchResponse(res);
    }

    // if current request is a regular http call, like page refresh, then check user authentication
    req.headers['authorization'] = 'Bearer ' + decryptedTokens.access_token;
    const failureRedirect = `${path}/login?redirect=` + encodeURIComponent(req.originalUrl);
    passport.authenticate(name + '_bearer', {
      session: false,
      response: res,
      failureRedirect,
    }, (err, user, info) => {
      if (err) { return next(err); }
      if (!user) {
        if (req.xhr || req.headers.accept.indexOf('json') > -1) {
          return res.status(401).location(`${path}/login`);
        } else {
          return res.redirect(failureRedirect);
        }
      }
      if (decryptedUserData) {
        try {
          const decryptedUserDataObject = JSON.parse(decryptedUserData);
          for (let prop in decryptedUserDataObject) {
            if (decryptedUserDataObject.hasOwnProperty(prop)) {
              user[prop] = decryptedUserDataObject[prop];
            }
          }
        } catch (e) { }
      }
      req.user = user;
      next();
    })(req, res, next);
  };

  const giveToken = (req, res, user, next) => {
    process.env.DEBUG && console.time('tokens encryption');
    const encryptedAccessToken = encrypt(user.access_token);
    const encryptedRefreshToken = encrypt(user.refresh_token);
    process.env.DEBUG && console.timeEnd('tokens encryption');

    // login from microsoft page - we can take roles and get real access token
    if (user.profile && user.profile._json && next) {
      try {
        const data = {
          roles: JSON.parse(user.profile._json.roles)
        };
        const encryptedData = encrypt(JSON.stringify(data));
        cookieParser.setCookie(req, res, `${name}_data`, encryptedData, { signed: true, maxAge: settings.cookie.refreshTokenAge });
        req.userData = data;
      } catch (e) { }
      refreshToken(user.refresh_token, req, res, next);
    } else {
      if (user.params) {
        const expirationTime = +user.params.expires_in * 1e3 - settings.bearer.timeToRenewBeforeExpiration;
        cookieParser.setCookie(req, res, `${name}_atoken`, encryptedAccessToken, { signed: true, maxAge: expirationTime });
      }
      cookieParser.setCookie(req, res, `${name}_rtoken`, encryptedRefreshToken, { signed: true, maxAge: settings.cookie.refreshTokenAge });
    }
  };

  return {
    checkAuth,
    giveToken,
    cookieParser
  };
}
