var App = require('../index').app;
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