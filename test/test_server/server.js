/*
 * --------------------------------------------------------
 * Enviornment setup
 * --------------------------------------------------------
 */
var express = require('express');
var https = require('https');
var fs = require('fs');
var passport = require('passport');
var DigestStrategy = require('passport-http').DigestStrategy;
var BasicStrategy = require('passport-http').BasicStrategy;
var dotenv = require('dotenv');
var bodyparser = require('body-parser');
var methodoverride = require('method-override');
var path = require('path');
var multipart = require('connect-multiparty');
var multipartMiddleware = multipart();

dotenv.load();

var logSize = 1048576;//10M
if(process.env.log_size){
  logSize = process.env.log_size;
}

var users = [
    {id: 1, username: 'bob', password: 'secret', email: 'bob@example.com' }
   ,{ id: 2, username: 'joe', password: 'birthday', email: 'joe@example.com' }
];

function findByUsername(username, fn) {
    for (var i = 0, len = users.length; i < len; i++) {
        var user = users[i];
        if (user.username === username) {
            return fn(null, user);
        }
    }
    return fn(null, null);
}
passport.use(new DigestStrategy({ qop: 'auth' },
    function(username, done) {
    // Find the user by username.  If there is no user with the given username
    // set the user to `false` to indicate failure.  Otherwise, return the
    // user and user's password.
        findByUsername(username, function(err, user) {
            if (err) { return done(err); }
            if (!user) { return done(null, false); }
            return done(null, user, user.password);
        })
    },
    function(params, done) {
        // asynchronous validation, for effect...
        process.nextTick(function () {
            // check nonces in params here, if desired
            return done(null, true);
        });
    }
));

passport.use(new BasicStrategy(
    function(username, password, done) {
        console.log(username + " " + password);
        if(username == 'bob' && password == 'secret')
            return done(null, username);
        else
            return done(null, false);
            /*
        User.findOne({ username: username }, function (err, user) {
        if (err) { return done(err); }
        if (!user) { return done(null, false); }
        if (!user.validPassword(password)) { return done(null, false); }
    });
        */
    }
));

HTTP_PORT=8888;
HTTPS_PORT=443;
SERVICE_PREFIX='/rest';
MISSING_PARAM='Missing parameter';
var ENABLE_DEBUG = true;


/*
 * --------------------------------------------------------
 * Setup server log
 * --------------------------------------------------------
 */
if(!fs.existsSync('log')){
  console.log("Log folder not exist, create it.\n");
  fs.mkdirSync('log', 0775, function(err){
    if(err){
      console.log("Log folder create failure.\n");
    }
  });
}
var winston = require('winston');

var logger = new (winston.Logger)({
  transports: [
    new (winston.transports.Console)({ json: false, timestamp: true }),
    new winston.transports.File({ filename: __dirname + '/log/debug.log', json: false , maxsize: logSize })
  ],
  exceptionHandlers: [
    new (winston.transports.Console)({ json: false, timestamp: true }),
    new winston.transports.File({ filename: __dirname + '/log/exceptions.log', json: false , maxsize: logSize})
  ],
  exitOnError: false
});

module.exports = logger;
var time = new Date();
TZ_OFFSET=time.getTimezoneOffset()*60;
logger.info("Server start at " + time );

/*
 * ==================================================
 *            Main Server
 * ==================================================
 */

var register = function(app){
  app.set('view engine', 'ejs');
  app.use(passport.initialize());
  app.use(bodyparser.json());
  app.use(bodyparser.urlencoded({ extended: false }));
  //app.use(busboy({ immediate: true }));
  //app.use(express.static(path.join(__dirname, 'html')));
  app.use(function(req, res, next){
    console.log('%s %s', req.method, req.url);
    next();
  });

/*
 * ==================================================
 *            App lookup device list
 * ==================================================
 */
  function client_authentication (req, res, next) {
    if(req.client.authorized){
        console.log ("authentication pass");
        next();
    } else {
        res.statusCode = 401
        res.end('Unauthorized');
    }
  }
  app.get('/ping'
          ,function(req, res){
    res.status(200).end();
  });
  app.get('/digest'
          ,passport.authenticate('digest', { session: false })
          ,function(req, res){
    var subject = req.connection.getPeerCertificate().subject;
    res.status(200).end(JSON.stringify(subject));
  });
  app.get('/basic'
          ,passport.authenticate('basic', { session: false })
          ,function(req, res){
    res.status(200).end("OK");
  });
  app.post('/pdigest'
          ,passport.authenticate('digest', { session: false })
          ,function(req, res){
    //var subject = req.connection.getPeerCertificate().subject;
    //res.status(200).end(JSON.stringify(subject));
    res.status(200).end();
  });
  app.post('/pbasic'
          ,passport.authenticate('basic', { session: false })
          ,function(req, res){
    res.status(200).end("OK");
  });
};

var http = express();
register(http);
http.listen(HTTP_PORT);

var options = {
  key: fs.readFileSync(__dirname + "/ssl.key"),
  cert: fs.readFileSync(__dirname + "/ssl.cert"),
  //passphrase: 'gemtek2014',
  ca:[fs.readFileSync(__dirname + "/ca.pem")],
  requestCert: true,
  rejectUnauthorized: false,
};
https.createServer(options, http).listen(HTTPS_PORT);
