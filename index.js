/*jslint node: true */
"use strict";

var debug = require('debug')('v1oauth');
var Q = require('q');
var request = require('superagent');
var fs = require('fs');
var path = require('path');
var util = require('util');
var events = require('events');

function AuthApp(secrets, options) {
  events.EventEmitter.call(this);
  var rootThis = this;
  var app = options.app;

  this.clientId = secrets.web.client_id;
  this.clientSecret = secrets.web.client_secret;
  this.authUri = secrets.web.auth_uri;
  this.tokenUri = secrets.web.token_uri;
  this.appBaseUrl = options.appBaseUrl;
  this.cacheDirectory = options.cacheDirectory || process.cwd();
  this.appReturnUrl = this.appBaseUrl + "/auth/versionone/callback";

  app.get('/start', function (req, res) {
    var authUri = rootThis.authUri +
      '?response_type=code' +
      '&client_id=' + rootThis.clientId +
      '&redirect_uri=' + rootThis.appReturnUrl +
      '&scope=ap1v1 query-api-1.0' +
      '&state=foobaz'; // TODO send more helpful state
    debug('/start redirecting to %s', authUri);
    res.redirect(authUri);
  });

  app.get('/auth/versionone/callback', function (req, res) {
    debug('serving /auth/versionone/callback with code %s', req.param('code'));
    var pageRes = res;
    var tokenPromise;
    if (req.param('code')) {
      debug('redeeming code for refreshToken');
      tokenPromise = rootThis.hitTokenUri({code: req.param('code')});
      tokenPromise.then(function fulfilled(tokensJson) {
        debug('got tokens!');
        rootThis.emit('refreshToken', tokensJson);
        pageRes.send('got token'); // TODO call next as middleware instead
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

AuthApp.prototype.url = function () {
  return this.appBaseUrl + "/start"; // TODO allow config
};

module.exports = AuthApp;