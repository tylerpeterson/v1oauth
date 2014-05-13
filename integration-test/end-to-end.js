/*jslint node: true, expr:true*/

var express = require('express');
var AuthApp = require('../index').app;
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
  var server;
  var port;
  var refreshToken;
  var accessToken;
  var browser;

  before(function () {
    browser = new Browser();
  });

  beforeEach(function () {
    app = express();
    auth = new AuthApp(secrets, {appBaseUrl: "http://localhost:8088"});
    app.get("/index", auth.restrict, function (req, res) {
      debug('get /index');
      res.send('<?html?><html><head><title>index page</title></head></html>');
    });
    app.use(auth.router);
    server = http.createServer(app);
    server.listen(8088);
    port = server.address().port;
    debug('on port %d', port);
  });

  afterEach(function () {
    server.close();
  });

  it('should issue a request', function () {
    this.timeout(5000);

    var url = auth.url();
    var tokensDfd = Q.defer();

    auth.on('refreshToken', function (tokens) {
      tokensDfd.resolve(tokens);
    });

    debug("opening web page", url);

    return Q.all([
      logInFlow(url),
      tokensDfd.promise.then(function (tokens) {
        expect(tokens).to.have.property('access_token').that.is.a('string', 'the emitted access token');
        expect(tokens).to.have.property('refresh_token').that.is.a('string', 'the emitted refresh token');
        expect(tokens).to.have.property('expires_in').that.equals(600, 'the emitted max age');
        expect(tokens).to.have.property('token_type').that.equals('bearer', 'the emitted token type');
      })
    ]);
  });

  it('should get new access token using refresh token', function () {
    this.timeout(5000);
    var url = "http://localhost:8088/index";

    browser.deleteCookie('v1accessToken');

    return browser.visit(url).then(function () {
      debug('verifying served page.');
      verifyAccessCookie();
    });
  });

  // TODO add another instance verifying what happens when the user denys the token
  it('should redirect to flow and back when no cookies set', function () {
    this.timeout(5000);
    var url = "http://localhost:8088/index";

    browser.deleteCookies();

    return logInFlow(url).then(function () {
      debug('done with flow.');
      expect(browser.text('title')).to.equal('index page');
    });
  });

  function logInFlow(url) {
    return browser.visit(url).then(function () {
      debug('loaded login page');
      return browser
          .fill('username', creds.username)
          .fill('password', creds.password)
          .pressButton('Login').then(function () {
            debug('on authorization page');
            return browser.pressButton('Allow').then(function () {
              debug('on final page');

              var refreshCookie = browser.getCookie('v1refreshToken', true);

              expect(refreshCookie).to.have.property('value').that.is.a('string', 'the refresh cookie value');
              expect(refreshCookie).to.have.property('expires').that.is.closeTo(Date.now() + 14 * ONE_DAY_MILLIS, 2000, 'the refresh cookie expiration date two weeks from now');
              expect(refreshCookie).to.have.property('secure').that.equals(true, 'the refresh cookie secure flag');
              refreshToken = refreshCookie.value; // Save for subsequent tests.  Hokey.

              verifyAccessCookie();
            });
          });
    });
  }

  function verifyAccessCookie() {
    var accessCookie = browser.getCookie('v1accessToken', true);
    
    expect(accessCookie, 'v1accessToken cookie').to.be.not.null;
    expect(accessCookie).to.have.property('value').that.is.a('string', 'the access token cookie value');
    expect(accessCookie).to.have.property('expires').that.is.closeTo(Date.now() + 600 * 1000, 2000, 'the access token cookie expiration date ten minutes from now');
    expect(accessCookie).to.have.property('secure').that.equals(true, 'the access token cookie secure flag');
    accessToken = accessCookie.value;    
  }
});