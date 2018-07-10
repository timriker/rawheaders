// node.js back end app to present SSO headers
// used by sso-facade, .NET sso emulator, and others
// by Tim Riker <Tim@LDSChurch.org>

// bare request gets headers in json and as headers
// calling with ?in=<url> does SSO signin and then redirects to url
// calling with ?out=<url> does SSO signout and then redirects to url
// cookiename is the cookie passed to the client to remember where to redirect to

var express = require('express');
var cookie = require('cookie');
var stringify = require('json-stable-stringify');

const cookiename = 'sso-redir';
var port =  process.env.PORT || 8081;
var app = express();

// Middleware
app.disable('x-powered-by');
app.set('trust proxy', true)
app.use(function(req, res, next) {
    if (req.get('host').indexOf('localhost') == -1) {
        // F5 keeps losing the X-Forwarded-Proto setting
        req.headers['x-forwarded-proto'] = 'https';
    }
    //console.log(req.headers);
    req.root = req.protocol + '://' + req.get('host');
    next();
});

app.get('/', function (req, res) {
    var signin = req.root + '?' + (req.headers["policy-signin"] || "signmein");
    var signout = req.root + '?' + (req.headers["policy-signout"] || "signmeout");
    res.setHeader('Expires', 'Sat, 26 Jul 1997 05:00:00 GMT');
    res.setHeader('Cache-Control', 'no-cache, must-revalidate');

    // save redirect and trigger WAM signin
    if (req.query.in) {
        res.cookie(cookiename, req.query.in, { path:'/', maxAge:3600000});
        res.redirect(signin);
    }

    // save redirect and trigger WAM signout
    if (req.query.out) {
        res.cookie(cookiename, req.query.out, { path:'/', maxAge:3600000});
        res.redirect(signout);
    }

    var cookies = cookie.parse(req.headers.cookie || '');
    // detect cookie and do redirect
    if (cookies[cookiename]) {
        res.clearCookie(cookiename, { path: '/' });
        res.redirect(cookies[cookiename]);
    }

    var reply = {};
    //reply.query = req.query;
    //reply.env = process.env;
    reply.cookies = cookies;
    reply.headers = {};
    reply.otherheaders = {};
    for (key in req.headers) {
        if (/policy/.test(key)) {
            res.setHeader(key, req.headers[key]);
            reply.headers[key] = req.headers[key];
        } else {
            reply.otherheaders[key] = req.headers[key];
        }
    }
    reply.links = {
        "self": req.root,
        "signin": signin,
        "signout": signout,
        "in": req.root + '?in=' + encodeURIComponent(req.root),
        "out": req.root + '?out=' + encodeURIComponent(req.root)
    };
    //console.log(reply);
    res.setHeader('Content-Type', 'application/json; charset=UTF-8');
    res.end(stringify(reply));
})

var server = app.listen(port, function () {
    var host = server.address().address
    var port = server.address().port

    console.log("Listening at http://%s:%s", host, port)
})