const bodyParser = require("body-parser");
const cookieParser = require('cookie-parser');
const OIDCStrategy = require('passport-azure-ad').OIDCStrategy;
const BearerStrategy = require('passport-azure-ad').BearerStrategy;
const merge = require('lodash').merge;

const getSettings = require('./settings');
const app = require("express")();

const authMiddleware = (clientConfig, baseName = '') => {
  const protectedPath = clientConfig.protectedPath || '/*';
  const passport = require('passport');
  const settings = getSettings(clientConfig);
  const path = baseName ? `/${baseName}` : '';
  const name = baseName || 'standalone';
  const utils = require('./utils')(path, name, settings);

  const strategyOIDC = new OIDCStrategy(
    settings.oidc,
    // Verification function
    (req, iss, sub, profile, access_token, refresh_token, params, done) => {
      return done(null, {
        profile,
        refresh_token,
        access_token,
        params
      });
    }
  );
  strategyOIDC.name = name;

  const strategyBearer = new BearerStrategy(
    settings.bearer,
    // Verification function
    (req, token, done) => {
      return done(null, token);
    }
  );
  strategyBearer.name = name + '_bearer';

  passport.use(strategyOIDC);
  passport.use(strategyBearer);

  app.use(cookieParser(settings.cookie.secret));

  // Use body-parser to parse the body of the POST request returned from the auth server
  app.use(bodyParser.urlencoded({ extended: true }));

  // Initialize passport
  app.use(passport.initialize());

  app.get(`${path}/login`, (req, res, next) => {
    const protocol = settings.oidc.forceProtocol || req.protocol;

    passport.authenticate(name, {
      session: false,
      response: res,
      resourceURL: '',
      failureRedirect: path || '/',
      customState: "/",
      extraAuthReqQueryParams: settings.oidc.allowAllHosts ? {
        'redirect_uri': protocol + '://' + req.headers.host + settings.oidc.redirectUrlPath
      } : {}
    })(req, res, next);
  });

  // Callback from the Azure AD login
  app.post(settings.oidc.redirectUrlPath, (req, res, next) => {
    const protocol = settings.oidc.forceProtocol || req.protocol;

    passport.authenticate(name, {
      session: false,
      response: res,
      failureRedirect: path || '/',
      extraTokenReqQueryParams: settings.oidc.allowAllHosts ? {
        'redirect_uri': protocol + '://' + req.headers.host + settings.oidc.redirectUrlPath
      } : {}
    }, (err, user) => {
      if (!err) {
        utils.giveToken(req, res, user, () => {
          res.redirect(req.body.state || '/');
        });
      } else {
        res.redirect(req.body.state || '/');
      }
    })(req, res, next);
  });

  // Logs the user out of their account
  app.get(`${path}/logout`, (req, res) => {
    const protocol = settings.oidc.forceProtocol || req.protocol;
    const redirectURL = settings.oidc.allowAllHosts ? protocol + '://' + req.headers.host : clientConfig.host;
    utils.cookieParser.clearCookie(req, res, `${name}_atoken`);
    utils.cookieParser.clearCookie(req, res, `${name}_rtoken`);
    utils.cookieParser.clearCookie(req, res, `${name}_data`);
    req.logout();
    res.redirect('https://login.microsoftonline.com/common/oauth2/logout?post_logout_redirect_uri=' + redirectURL);
  });

  app.all(protectedPath, utils.checkAuth, (req, res, next) => {
    req.headers['cookie'] = '';
    next();
  });

  return app;

}

module.exports = authMiddleware;
