// node.js back end app to present SSO headers
// used by stack-facade, .NET sso emulator, and others
// by Tim Riker <Tim@Rikers.org>

// bare request gets headers in json and as headers
// calling with ?in=<url> does SSO signin and then redirects to url
// calling with ?out=<url> does SSO signout and then redirects to url
// cookiename is the cookie passed to the client to remember where to redirect to

const express = require('express');
const cookie = require('cookie');
const emailjsMimeCodec = require('emailjs-mime-codec');
const jwtDecode = require('jwt-decode');
const process = require('process');

const cookiename = 'header-redir';
var port = process.env.PORT || 8081;
var host = process.env.HOST || '';
var app = express();

// Middleware
app.use(express.urlencoded({ extended: true }));
app.disable('x-powered-by');
app.set('trust proxy', true)
app.set('json spaces', 4);
app.set('view engine', 'ejs');
app.use(function(req, res, next) {
    if (req.get('host') && req.get('host').indexOf('localhost') == -1) {
        // F5 keeps losing the X-Forwarded-Proto setting
        //req.headers['x-forwarded-proto'] = 'https';
    }
    //console.log(req.headers);
    req.root = req.protocol + '://' + req.host + req.path;
    //console.log(req.root);
    next();
});

// restrict access to /reflect and WAM can log you in and you bounce back to where you came from
app.all('*/reflect', function (req, res){
    // referer is lost. it will contain the login/signin url and not the original requester
    res.redirect(307, '..').end();
});

app.head('/*', function (req, res) {
    // return policy headers on HEAD requests
    for (key in req.headers) {
        if (/policy/.test(key)) {
            res.setHeader(key, req.headers[key]);
        }
    };
    res.end();
});

app.all('/*', function (req, res) {
    var signin = req.root + '?' + (req.headers['policy-signin'] || 'signmein');
    var signout = req.root + '?' + (req.headers['policy-signout'] || 'signmeout');
    res.setHeader('Expires', 'Sat, 26 Jul 1997 05:00:00 GMT');
    res.setHeader('Cache-Control', 'no-cache, must-revalidate');

    // save redirect and trigger WAM signin
    if (req.query.in) {
        res.cookie(cookiename, req.query.in, { path:'/', maxAge:3600000});
        res.redirect(307, signin);
        return;
    }

    // save redirect and trigger WAM signout
    if (req.query.out) {
        res.cookie(cookiename, req.query.out, { path:'/', maxAge:3600000});
        res.redirect(307, signout);
        return;
    }

    var cookies = cookie.parse(req.headers.cookie || '');
    // detect cookie and do redirect
    if (cookies[cookiename]) {
        res.clearCookie(cookiename, { path: '/' });
        res.redirect(307, cookies[cookiename]);
        return;
    };

    var status = 200;
    var delay = 0;
    var production = true;
    if (/(localhost|-(dev|test|stage|int|uat|load)\.)/i.test(req.hostname)) {
        production = false;
    }

    // delay for delayed reply
    if (!production && !isNaN(req.query.delay)) {
        delay = parseInt(req.query.delay);
    }

    // status for manual status code
    if (!production && !isNaN(req.query.status)) {
        status = parseInt(req.query.status);
    }

    var reply = {};
    //reply.query = req.query;
    //reply.env = process.env;
    var reflect = '';
    if (req.root.endsWith('/')) {
        reflect = req.root + 'reflect';
        relreflect = './reflect';
    } else {
        reflect = req.root + '/reflect';
        relreflect = req.path + '/reflect';
    }
    reply.links = {
        'html': req.root + '?format=html',
        'json': req.root + '?format=json',
        'in': req.root + '?in=' + encodeURIComponent(req.root),
        'out': req.root + '?out=' + encodeURIComponent(req.root),
        'reflect': reflect,
        'relreflect': relreflect,
        'self': req.root,
        'signin': signin,
        'signout': signout
    };
    reply.headers = {};
    reply.otherheaders = {};
    for (key in req.headers) {
        if (/^policy/.test(key)) {
            if (production && (/^policy-(ldsmrn|ldsbdate|workforceid)/i.test(key))) {
                reply.headers[key] = '*****';
            } else {
                reply.headers[key] = req.headers[key];
            }
        } else {
            reply.otherheaders[key] = req.headers[key];
        }
    };
    Object.keys(reply.headers).forEach(function(prop) {
        if (reply.headers[prop].startsWith('=?')) {
            reply.headers[prop+'-decoded'] = emailjsMimeCodec.mimeWordsDecode(reply.headers[prop]);
        }
    });
    reply.info = {
        'date': (new Date()).toISOString(),
        'header_count': Object.keys(req.headers).length,
        'header_size': JSON.stringify(req.headers).length,
        'host': req.host,
        'hostname': req.hostname,
        'httpversion': req.httpVersion,
        'ip': req.ip,
        'method': req.method,
        'originalurl': req.originalUrl,
        'path': req.path,
        'query': JSON.stringify(req.query),
        'root': req.root,
        'url': req.url
    };
    if (!production) {
        reply.info['delay'] = delay;
        reply.info['status'] = status;
        reply.info['versions'] = JSON.stringify(process.versions);
    }
    reply.cookies = cookies;
    Object.keys(cookies).forEach(function(prop) {
        try {
            reply.cookies[prop+'-decoded'] =
                JSON.stringify(jwtDecode(cookies[prop], { header: true })) +
                JSON.stringify(jwtDecode(cookies[prop]));
        } catch(e) {}
    });
    setTimeout(function() {
        if (req.accepts('html') && (req.query.format === undefined || req.query.format === 'html')) {
            // html page if supported
            res.status(status).render('pages/request.ejs', { 'reply': reply });
        } else {
            // otherwise json
            res.status(status).json(reply);
        }
    }, delay);
})

var server = app.listen(port, host, function () {
    var host = server.address().address;
    var port = server.address().port;

    console.log('Listening at http://%s:%s', host, port);
})
