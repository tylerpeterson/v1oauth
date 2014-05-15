var express = require('express');
var AuthApp = require('../index').app;
var secrets = require('../client_secrets');
var app = express();
var auth = new AuthApp(secrets, {appBaseUrl: "http://localhost:8088", secureCookies: false});
var debug = require('debug')('v1oauth');

app.get("/index", auth.restrict, function (req, res) {
  debug('get /index');
  res.send('<?html?><html><head><title>index page</title></head><body>index body</body></html>');
});
app.use(auth.router);
app.listen(8088);
