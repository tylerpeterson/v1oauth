/*jslint node: true */
"use strict";

var debug = require('debug')('v1oauth');
var Q = require('q');
var request = require('superagent');
var fs = require('fs');
var path = require('path');
var util = require('util');
var events = require('events');
var express = require('express');
var TWO_WEEKS_IN_MILLIS = 14 * 24 * 60 * 60 * 1000;
var cookieParser = require('cookie-parser');

function AuthApp(secrets, options) {
  events.EventEmitter.call(this);
  var rootThis = this;
  var app = this.router = express.Router();

  secrets = secrets || {web:{}};
  options = options || {};

  this.clientId = secrets.web.client_id;
  this.clientSecret = secrets.web.client_secret;
  this.authUri = secrets.web.auth_uri;
  this.tokenUri = secrets.web.token_uri;
  this.appBaseUrl(options.appBaseUrl);
  this.cacheDirectory = options.cacheDirectory || process.cwd();
  this.secureCookies = options.secureCookies !== undefined ? options.secureCookies : true;

  this.restrict = this.restrict.bind(this);

  app.get('/start', function (req, res) {
    debug('/start redirecting to v1oauth flow');
    rootThis.redirectToV1Auth(null, res);
  });

  app.get('/auth/versionone/callback', function (req, res) {
    debug('serving /auth/versionone/callback with code %s', req.param('code'));
    var pageRes = res;
    var tokenPromise;
    var state = req.param('state');
    var returnUrl = decodeURIComponent(state);
    if (req.param('code')) {
      debug('redeeming code for refreshToken');
      tokenPromise = rootThis.hitTokenUri({code: req.param('code')});
      tokenPromise.then(function fulfilled(tokensJson) {
        rootThis.handleTokensBody(tokensJson, pageRes);

        // TODO create an endpoint for deleting the access token cookie. Leave the refresh token cookie.
        // TODO consider how a command-line tool will use the library. Perhaps will still need to emit events for that use-case.
        rootThis.emit('refreshToken', tokensJson);
        if (state && returnUrl) {
          debug('code redeemed. Flow complete. Redirecting to %s', returnUrl);
          return pageRes.redirect(returnUrl);
        }
        pageRes.send('<?html?><html><head><title>got token</title></head></html>'); // TODO call next as middleware instead
        pageRes.end();
      }, function rejected(errMessage) {
        // TODO emit an error event
        pageRes.send('failed to get token'); // TODO call next as middleware instead
        pageRes.end();
      });
    } else {
      // TODO emit an error event
      res.send("Didn't get authorization code!"); // TODO call next as middleware instead
      res.end();
    }
  });
}

util.inherits(AuthApp, events.EventEmitter);

AuthApp.prototype.handleTokensBody = function (tokensJson, pageRes) {
  debug('got tokens!', tokensJson);

  // The refresh token can't be used to gain access without the client secret. Set it in a cookie that doesn't expire.
  pageRes.cookie('v1refreshToken', tokensJson.refresh_token, {maxAge: TWO_WEEKS_IN_MILLIS, secure: this.secureCookies});
  // The access token lets anyone masquerade as the user, but expires in ten minutes. Set it in a cookie that expires appropriately.
  pageRes.cookie('v1accessToken', tokensJson.access_token, {maxAge: tokensJson.expires_in * 1000, secure: this.secureCookies});
};

/** Resolve an authorization code OR a refresh token into an access token.
 * Must be called with either
 *   {code: "**authorization code from oauth flow calback**"}
 *   -- OR --
 *   {refreshToken: "**refresh token from previous successful flow**"}
 */
AuthApp.prototype.hitTokenUri = function (params) {
  var dfd = Q.defer();
  var tokenRequest = request.post(this.tokenUri)
        .send('client_id=' + this.clientId)
        .send('client_secret=' + this.clientSecret);

  if (params.code) {
    tokenRequest = tokenRequest
      .send('code=' + params.code)
      .send('grant_type=authorization_code')
      .send('redirect_uri=' + this.appReturnUrl)
      .send('scope=apiv1 query-api-1.0');
  } else if (params.refreshToken) {
    tokenRequest = tokenRequest
      .send('refresh_token=' + params.refreshToken)
      .send('grant_type=refresh_token');
  } else {
    dfd.reject('must call with code or refreshToken');
  }
  tokenRequest
    .end(function (res) {
      if (res.ok) {
        dfd.resolve(res.body);
      } else {
        dfd.reject("error getting access token", res.text);
      }
    });
  return dfd.promise;
};

AuthApp.prototype.appBaseUrl = function(appBaseUrl) {
  if (typeof appBaseUrl === 'string') {
    this._appBaseUrl = appBaseUrl;
    this.appReturnUrl = this._appBaseUrl + "/auth/versionone/callback";
  }
  return this._appBaseUrl;
};

AuthApp.prototype.url = function () {
  return this._appBaseUrl + "/start"; // TODO allow config
};

AuthApp.prototype.redirectToV1Auth = function(req, res) {  
  var state = '';
  var authUri;

  if (req) {
    state = encodeURIComponent(req.originalUrl);
  }

  authUri = this.authUri +
    '?response_type=code' +
    '&client_id=' + this.clientId +
    '&redirect_uri=' + this.appReturnUrl +
    '&scope=ap1v1 query-api-1.0' +
    (state ? '&state=' + state : '');
  debug('redirecting to %s', authUri);
  res.redirect(authUri);
};

AuthApp.prototype.restrict = function(req, res, next) {
  debug('AuthApp.restrict');
  var self = this;

  function finish() {
    debug('cookies parsed', req.cookies);
    if (req.cookies.v1accessToken) {
      debug('already have v1accessToken. Proceed.');
      return next();
    }
    if (req.cookies.v1refreshToken) {
      debug('missing v1accessToken. Have v1refreshToken. Attempt refresh.');
      return self.hitTokenUri({refreshToken: req.cookies.v1refreshToken}).then(function (tokensJson) {
        self.handleTokensBody(tokensJson, res);
        // TODO make sure tokens are available on THIS request and not just set cookies for next request.
        next();
      });
    }
    debug('no v1oauth cookies. Redirect to oauth flow.');
    self.redirectToV1Auth(req, res);
  }

  if (req.cookies) {
    finish();
  } else {
    cookieParser()(req, res, finish);
  }
};

module.exports = {
  app: AuthApp
};