var Express = require('express');
var serveStatic = require('ecstatic');
var passport = require('passport');
var fileUpload = require('express-fileupload');
var async = require('async');
var bodyParser = require('body-parser')
var session = require('express-session');
var FileStore = require('session-file-store')(session);
var passwordManager = require('./lib/password-manager');
var LocalStrategy = require('passport-local').Strategy;
var _ = require('lodash');
var cookieParser = require('cookie-parser');


// env vars
// set these plus LOGINHASH using hash.js
var port = process.env.PORT || 8080;
var videoDir = process.env.VIDEODIR || './videos';
var sessionSecret = process.env.SESSIONSECRET || "YOU NEED TO FILL THIS OUT"

var app = Express();

var parseFormBody = bodyParser.urlencoded({extended:false});
var parseJsonBody = bodyParser.json({extended:false});

app.use(serveStatic({root:'public'}));
app.use(serveStatic({root:videoDir,'baseDir':'videos'}));

/*
  stuff for passport
*/
app.use(session({
  name: 'JSESSION',
  secret: sessionSecret,
  store: new FileStore({
    path:"./.sessions"
  })
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(cookieParser());

app.post('/login',
  parseFormBody,
  passport.authenticate('local', {
    successRedirect: '/?admin',
    failureRedirect: '/login?failure',
    failureFlash: false
  }),function(req,res){
    //console.log(req.user);
  }
);

function ensureAuthenticated(req,res,next){
  //console.log(req.user);
  if (req.isAuthenticated()){
    return next();
  }else{
    res.status(401);
    res.send();
  }
}

function ensureAuthenticatedRedirect(req,res,next){
  if (req.isAuthenticated()){
    return next();
  }else{
    res.redirect('/login');
  }
}

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  return done(null,{id:id});
});

// where the magic happens
passport.use(new LocalStrategy(
  function(username, password, done) {
    passwordManager.check(password,function(er,ok){
      if (er) {
        return done(er);
      }
      if (!ok){
        return done( null,false,{message:'bad password'} )
      }
      return done(null,{id:'admin'});
    })
  }
));

// socketio

var server = require('http').createServer(app);
var io = require('socket.io')(server);

io.on('connection', function(socket){
  //console.log('a user connected');
  socket.on('chat message', function(msg){
      io.emit('chat message', msg);
    });
});

// socketio auth is a todo
/*
io.use(passportSocketIo.authorize({
  cookieParser: cookieParser,       // the same middleware you registrer in express
  key:          'express.sid',       // the name of the cookie where express/connect stores its session_id
  secret:       'session_secret',    // the session_secret to parse the cookie
  store:        sessionStore,        // we NEED to use a sessionstore. no memorystore please
  success:      onAuthorizeSuccess,  // *optional* callback on success - read more below
  fail:         onAuthorizeFail,     // *optional* callback on fail/error - read more below
}));

function onAuthorizeSuccess(data, accept){
  console.log('successful connection to socket.io');

  // The accept-callback still allows us to decide whether to
  // accept the connection or not.
  accept(null, true);
}
*/

// in the future: file upload from the web interface
/*

for now do it yourself

// put an asset up
app.post('/admin/file',ensureAdmin,fileUpload(),function(req,res){
  // path comes from querystring
  //console.log('posted upload');
  var dest = req.query.path||req.query.destination||videoDir;
  if (!req.files){
    res.status(400);
    return res.send('no files!')
  }
  // array of files
  var files = Object.keys(req.files).map(function(k){
    return {
      file:req.files[k],
      dest:req.query.filename?path.join(process.cwd(),req.query.filename):path.join(process.cwd(),dest,req.files[k].name)
    };
  });

  async.each(files,function iterator(file,callback){
    file.file.mv(file.dest,callback);
  },function done(er){
    if (er){
      console.error(er);
      res.status(500);
      return res.send(er)
    }
    res.status(200);
    // get filenames to return to client
    var ret = files.map( function(file){
      return {
        name:file.file.name,
        href:file.dest.replace(srcDir+'/','')
       }
    });

    return res.json(ret);
  });
});

app.delete('/admin/asset',ensureAuthenticated,function(req,res){
  if (!req.query || !req.query.filename){
    res.status(400);
    return res.send('you must provide an asset filename to delete')
  }
  var filename = path.join(process.cwd(),'assets',req.query.filename);
  fs.stat(filename,er=>{
    if (er){
      res.status(500);
      return res.send(er)
    }
    fs.unlink(filename,er=>{
      if (er){
        res.status(500);
        return res.send(er)
      }
      res.status(200);
      return res.send();
    });
  });

});

*/

/*
sync file and time
 note that 'now' always returns latest datetime for sync
 syncTime is the time the change happened
 trackposition is track time in seconds when the change happened
*/
var sync = {
  file:'videos/bbb.mp4',
  trackPosition:0,
  paused:false,
  syncTime:Date.now(),
  get now(){
    return Date.now()
  }
};

function emitSync(){
  io.emit('sync',sync);
}
setInterval(emitSync,5000);

app.get('/sync',function(req,res){
  res.status(200);
  return res.json(sync);
})

// this is how the sync object is updated
app.post('/sync',ensureAuthenticated,parseJsonBody,function(req,res){

  if (!req.body){
    res.status(500);
    return res.send();
  }

  _.assign(sync,req.body);
  sync.syncTime = Date.now();

  res.status(200);
  res.send();

  emitSync();
});

var port = process.env.PORT || 8080;
server.listen(port,function(){
    console.log("listening on port "+port);
});
