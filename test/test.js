var v1oauth = require('../index');
var App = v1oauth.app;
var expect = require('chai').expect;
var debug = require('debug')('v1oauth');

describe('AuthApp', function () {
  it('should accept config in constructor for baseurl', function () {
    var app = new App(null, {appBaseUrl: 'a/test/value'});
    expect(app).to.respondTo('appBaseUrl');
    expect(app.appBaseUrl()).to.equal('a/test/value');
  });
  it('should accept baseurl config after construction', function () {
    var app = new App();
    app.appBaseUrl('another/test/value');
    expect(app.appBaseUrl()).to.equal('another/test/value');
  });
});

describe('authService', function () {
  it('should be exported as function v1oauth.authService', function () {
    expect(v1oauth).to.respondTo('authService');
  });

  it('should expose the server base url', function () {
    var sut = v1oauth.authService({ web: { server_base_uri: "https://example.com/instance"}});
    expect(sut).to.have.property('serverBaseUri', "https://example.com/instance");
  });  
});