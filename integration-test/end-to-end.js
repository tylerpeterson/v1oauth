var express = require('express');
var AuthApp = require('../index.js').app;
var secrets = require('../client_secrets');
var http = require('http');
var debug = require('debug')('v1oauth');
var expect = require('chai').expect;
var Browser = require('zombie');
var creds = require('../user_secrets');
var Q = require('q');

var ONE_DAY_MILLIS = 24 * 60 * 60 * 1000;

describe('ManualAuthApp', function () {
  var auth;
  var app;

  beforeEach(function () {
    app = express();
    auth = new AuthApp(secrets, {appBaseUrl: "http://localhost:8088"});
    app.use(auth.router);
  });

  it('should issue a request', function () {
    this.timeout(5000);

    var server = http.createServer(app);
    var url = auth.url();
    var tokensDfd = Q.defer();

    server.listen(8088);
    auth.on('refreshToken', function (tokens) {
      tokensDfd.resolve(tokens);
    });

    debug("opening web page", url);

    var browser = new Browser();
    return Q.all([
      browser.visit(url).then(function () {
        debug('loaded login page');
        return browser
            .fill('username', creds.username)
            .fill('password', creds.password)
            .pressButton('Login').then(function () {
              debug('on authorization page');
              return browser.pressButton('Allow').then(function () {
                debug('on final page');

                var refreshCookie = browser.getCookie('v1refreshToken', true);
                var accessCookie = browser.getCookie('v1accessToken', true);

                expect(refreshCookie).to.have.property('value').that.is.a('string', 'the refresh cookie value');
                expect(refreshCookie).to.have.property('expires').that.is.closeTo(Date.now() + 14 * ONE_DAY_MILLIS, 2000, 'the refresh cookie expiration date two weeks from now');
                expect(refreshCookie).to.have.property('secure').that.equals(true, 'the refresh cookie secure flag');

                expect(accessCookie).to.have.property('value').that.is.a('string', 'the access token cookie value');
                expect(accessCookie).to.have.property('expires').that.is.closeTo(Date.now() + 600 * 1000, 2000, 'the access token cookie expiration date ten minutes from now');
                expect(accessCookie).to.have.property('secure').that.equals(true, 'the access token cookie secure flag');
              });
            });
      }),
      tokensDfd.promise.then(function (tokens) {
        expect(tokens).to.have.property('access_token').that.is.a('string', 'the emitted access token');
        expect(tokens).to.have.property('refresh_token').that.is.a('string', 'the emitted refresh token');
        expect(tokens).to.have.property('expires_in').that.equals(600, 'the emitted max age');
        expect(tokens).to.have.property('token_type').that.equals('bearer', 'the emitted token type');
      })
    ]);
  });
  // TODO add another test that uses refresh token to gain new access token
  // TODO add another instance verifying what happens when the user denys the token
});