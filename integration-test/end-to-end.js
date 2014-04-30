var express = require('express');
var AuthApp = require('../index.js');
var secrets = require('../client_secrets');
var http = require('http');
var debug = require('debug')('v1oauth');
var expect = require('chai').expect;
var Browser = require('zombie');
var creds = require('../user_secrets');

describe('ManualAuthApp', function () {
  var auth;
  var app;

  beforeEach(function () {
    app = express();
    auth = new AuthApp(secrets, {appBaseUrl: "http://localhost:8088"});
    app.use(auth.router);
  });

  it('should issue a request', function (done) {
    this.timeout(5000);
    var server = http.createServer(app);
    var url = auth.url();
    server.listen(8088);

    debug("opening web page", url);

    var browser = new Browser();
    browser.visit(url, function () {
      debug('loaded login page');
      browser
          .fill('username', creds.username)
          .fill('password', creds.password)
          .pressButton('Login', function () {
            debug('on authorization page');
            browser.pressButton('Allow');
          });
    });

    auth.on('refreshToken', function (tokens) {
      try {
        debug('caught refreshToken event');
        expect(tokens).to.have.property('access_token');
        expect(tokens).to.have.property('refresh_token');
        expect(tokens).to.have.property('expires_in'); // should be 600
        expect(tokens).to.have.property('token_type');
        expect(tokens.token_type).to.equal('bearer');
        debug('got tokens', tokens);
        done();
      } catch (err) {
        done(err);
      }
    });
  });
  // TODO add another test that uses refresh token to gain new access token
  // TODO add another instance verifying what happens when the user denys the token
});