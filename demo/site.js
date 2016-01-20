var express = require('express');
var AuthApp = require('../index').app;
var secrets = require('../client_secrets');
var app = express();
var auth = new AuthApp(secrets, {appBaseUrl: "http://localhost:8088", secureCookies: false});
var debug = require('debug')('v1oauth');
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var request = require('superagent');
var serverBaseUri = secrets.web.server_base_uri;

app.use(bodyParser());
app.use(cookieParser());

app.get("/index", auth.restrict, function (req, res) {
  debug('get /index');
  res.send('<?html?><html><head><title>index page</title></head><body>' +
    '<form method="post">' +
    '<textarea name="query" cols=80 rows=20>' +
    '{\n' +
    '  "from": "Member",\n' +
    '  "select": [\n' +
    '    "Name",\n' +
    '    "Nickname"\n' +
    '  ]\n' +
    '}' +
    '</textarea>' +
    '<button>Submit</button>' +
    '</form>' +
    '</body></html>');
});
app.post('/index', auth.restrict, function (req, res) {
  debug('post /index');
  var queryText = req.param('query');
  var queryObject = null;
  var token = req.cookies.v1accessToken;
  var pageRes = res;
  debug('getting url %s', serverBaseUri + '/query.v1');

  try {
    queryObject = JSON.parse(queryText);
  } catch (err) {
    if (err instanceof SyntaxError) {
      console.dir(err);
      renderResults(pageRes, queryText, 'syntax error in your JSON\n' + err.message);
    } else {
      throw err;
    }
  }
  if (queryObject) {
    request
      .get(serverBaseUri + '/query.v1')
      .set('Authorization', 'Bearer ' + token)
      .send(queryObject)
      .end(function (err, res) {
        var results;

        if (err === null) {
          debug('successful request!');
          results = 'success!\n' + JSON.stringify(res.body, null, 2);
        } else {
          debug("failed to get data");
          results = 'failure :(\n' + res.text;
        }
        renderResults(pageRes, queryText, results);
      });
  }
});
app.get('/', function(req, res) {
  res.redirect('/index');
});
function renderResults(res, queryText, results) {
  res.send('<?html?><html><head><title>index page</title></head><body>' +
    '<form method="post">' +
    '<textarea name="query" cols=80 rows=20>' +
    queryText +
    '</textarea>' +
    '<button>Submit</button>' +
    '</form>' +
    '<pre>' +
    results +
    '</pre>' +
    '</body></html>');
}
app.use(auth.router);
app.listen(8088);
