const express = require('express'),
    exphbs = require('express-handlebars'),
    logger = require('morgan'),
    cookieParser = require('cookie-parser'),
    bodyParser = require('body-parser'),
    methodOverride = require('method-override'),
    session = require('express-session'),
    passport = require('passport'),
    LocalStrategy = require('passport-local'),
    TwitterStrategy = require('passport-twitter'),
    FacebookStrategy = require('passport-facebook'),
    GoogleStrategy = require('passport-google-oauth').OAuth2Strategy,
    request = require('request'),
    app = express(),
    MongoClient = require('mongodb').MongoClient,
    // yelp = require('yelp-fusion'),
    // asyncx = require('async'),
    qs = require('qs'),
    bcrypt = require('bcryptjs');


    var config = require('./config.js');
    var funct = require('./functions.js');
    var User = require('./users.js');


    var mongodbUrl = config.mongodbUri;


function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) { return next(); }
  req.session.error = 'Please sign in!';
  res.redirect('/signin');
}


// app.use(logger('combined'));
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(methodOverride('X-HTTP-Method-Override'));
app.use(session({secret: 'supernova', saveUninitialized: true, resave: true}));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static('static'))


passport.use('local-signin', new LocalStrategy(
  {passReqToCallback : true}, //allows us to pass back the request to the callback
  function(req, username, password, done) {
    funct.localAuth(username, password)
    .then(function (user) {
      if (user) {
        console.log("LOGGED IN AS: " + user.username);
        req.session.success = 'You are successfully logged in ' + user.username + '!';
        done(null, user);
      }
      if (!user) {
        console.log("COULD NOT LOG IN");
        req.session.error = 'Could not log user in. Please try again.'; //inform user could not log them in
        done(null, user);
      }
    })
    .fail(function (err){
      console.log(err.body);
    });
  }
));

// Use the LocalStrategy within Passport to register/"signup" users.
passport.use('local-signup', new LocalStrategy(
  {passReqToCallback : true}, //allows us to pass back the request to the callback
  function(req, username, password, done) {
    funct.localReg(req, username, password)
    .then(function (user) {
      if (user) {
        console.log("REGISTERED: " + user.displayName);
        req.session.success = 'You are successfully registered and logged in ' + user.displayName + '!';
        done(null, user);
      }
      if (!user) {
        console.log("COULD NOT REGISTER");
        req.session.error = 'That username is already in use, please try a different one.'; //inform user could not log them in
        done(null, user);
      }
    })
    .fail(function (err){
      console.log(err.body);
    });
  }
));


passport.use(new TwitterStrategy({
    consumerKey: config.TWITTER_CONSUMER_KEY,
    consumerSecret: config.TWITTER_CONSUMER_SECRET,
    callbackURL: config.url + "auth/twitter/callback"
  },
  function(token, tokenSecret, profile, cb) {
    User.findOrCreate(profile, cb);
  }
));


passport.use(new GoogleStrategy({
    clientID: config.GOOGLE_CLIENT_ID,
    clientSecret: config.GOOGLE_CLIENT_SECRET,
    callbackURL: config.url + "auth/google/callback"
  },
  function(accessToken, refreshToken, profile, done) {
      User.findOrCreate(profile, done);
  }
));

passport.use(new FacebookStrategy({
    clientID: config.FACEBOOK_CLIENT_ID,
    clientSecret: config.FACEBOOK_CLIENT_SECRET,
    callbackURL: config.url + "auth/facebook/callback"
  },
  function(accessToken, refreshToken, profile, done) {
      User.findOrCreate(profile, done);
  }
));


passport.serializeUser(function(user, done) {
  console.log("serializing " + user.username);
  done(null, user._id);
});

passport.deserializeUser(function(obj, done) {
  console.log("deserializing " + obj);
  MongoClient.connect(mongodbUrl, function (err, db) {
      var collection = db.collection('users');
      collection.findOne({_id: require('mongodb').ObjectID(obj)}).then(function(result){
          done(null, result);
      });
  });
});


app.use(function(req, res, next){
  var err = req.session.error,
      msg = req.session.notice,
      success = req.session.success;

  delete req.session.error;
  delete req.session.success;
  delete req.session.notice;

  if (err) res.locals.error = err;
  if (msg) res.locals.notice = msg;
  if (success) res.locals.success = success;

  next();
});



var hbs = exphbs.create({ defaultLayout: 'main', helpers: require('./handlebars-helpers.js').helpers });
app.engine('handlebars', hbs.engine);
app.set('view engine', 'handlebars');



app.get('/', function(req, res){
    res.render('home', {user: req.user, title: 'Book Trade'});
});

app.get('/mybooks', function(req, res){
    MongoClient.connect(mongodbUrl, function (err, db) {
        var collection = db.collection('books');
        var trade = db.collection('trade');
        collection.find().toArray(function(err, results) {
            trade.find({from: require('mongodb').ObjectID(req.user._id)}).toArray(function(err1, requests) {
                trade.find({to: require('mongodb').ObjectID(req.user._id)}).toArray(function(err1, offers) {
                    res.render('mybooks', {user: req.user, books: results, requests: requests, offers: offers, reqNum: requests.length, offNum: offers.length, title: 'Book Trade | My Books'});

                });
            });
        });
    });
});


app.get('/allbooks', function(req, res){
    MongoClient.connect(mongodbUrl, function (err, db) {
        var collection = db.collection('books');
        var trade = db.collection('trade');
        collection.find().toArray(function(err, results) {
            trade.find({from: require('mongodb').ObjectID(req.user._id)}).toArray(function(err1, requests) {
                trade.find({to: require('mongodb').ObjectID(req.user._id)}).toArray(function(err1, offers) {
                    res.render('allbooks', {user: req.user, books: results, requests: requests, offers: offers, reqNum: requests.length, offNum: offers.length, title: 'Book Trade | All Books'});

                });
            });
        });
    });
});


app.get('/addbook', function(req, res){
    request('https://www.googleapis.com/books/v1/volumes?q=' + req.query.q + '&maxResults=1&printType=books&projection=lite&langRestrict=en&orderBy=relevance', function (error, response, body) {
        console.log('error:', error); // Print the error if one occurred
        var body = JSON.parse(body);
        var obj = {
            title: body.items[0].volumeInfo.title,
            img: body.items[0].volumeInfo.imageLinks.smallThumbnail
        }
        MongoClient.connect(mongodbUrl, function (err, db) {
            var collection = db.collection('books');
            collection.insert({bookId: body.items[0].id, userId: req.user._id, title: obj.title, img: obj.img}, function(err, data) {

                res.json(data.ops[0]);

            });
        });
    });


});


app.get('/tradebook', function(req, res){
    MongoClient.connect(mongodbUrl, function (err, db) {
        var books = db.collection('books');
        var trade = db.collection('trade');
        books.findOne({_id: require('mongodb').ObjectID(req.query.q)}).then(function(result) {
            trade.findOne({from: result.userId, to: req.user._id, bookId: req.query.q, title: result.title , img: result.img}).then(function(exist) {
                if (exist) {
                    res.json({status: "no"});
                } else {
                    trade.insert({from: req.user._id, to: result.userId, bookId: req.query.q, title: result.title , img: result.img}, function(err, data) {
                        res.json({status: "ok"});
                    });
                }
            })
        });
    });


});


app.get('/removetrade', function(req, res){
    MongoClient.connect(mongodbUrl, function (err, db) {
        var trade = db.collection('trade');
        trade.remove({_id: require('mongodb').ObjectID(req.query.q)}, function(err, result) {
            res.json({status: "ok"});
        });
    });


});


app.get('/deletebook', function(req, res){
    MongoClient.connect(mongodbUrl, function (err, db) {
        var collection = db.collection('books');
        collection.remove({_id: require('mongodb').ObjectID(req.query.q)}, function() {
            res.json({status: "ok"});
        });
    });

});


app.get('/set', function(req, res){

    res.render('set', {user: req.user, title: 'Book Trade | Setting' });
});


app.post('/setinfo', function(req, res) {
    MongoClient.connect(mongodbUrl, function (err, db) {
        var collection = db.collection('users');
        var obj = {};
        if (req.body.city) {
            obj['city'] = req.body.city;
        }
        if (req.body.state) {
            obj["state"] = req.body.state;
        }
        collection.update({_id : require('mongodb').ObjectID(req.user._id)}, { $set: obj}, function(err) {
            console.log(err);
            req.session.success = 'You are successfully changed your city and state!';
            res.redirect('set');
        });
    });

});



app.post('/setpass', function(req, res) {

    var hash = req.user.password;

    if (bcrypt.compareSync(req.body.password, hash)) {
        if (req.body.newPassword.length < 3) {
            req.session.error = 'New Password Should Be 3 Or More Chars!';
            res.redirect('/set');
        } else {
            MongoClient.connect(mongodbUrl, function (err, db) {
                var collection = db.collection('users');
                var hash1 = bcrypt.hashSync(req.body.newPassword, 8);

                collection.update({_id : require('mongodb').ObjectID(req.user._id)}, { $set: { password: hash1 } }, function(err) {
                    console.log(err);
                    req.session.success = 'You are successfully changed your city and state!';
                    res.redirect('/set');
                });
            });
        }
    } else {
      req.session.error = 'Your password is not correct!';
      res.redirect('/set');
    }

});



app.get('/signin', function(req, res){
    req.session.q = req.query.q;
    res.render('signin', { title: 'Book Trade | Sign In' } );
});

app.post('/local-reg', passport.authenticate('local-signup', {
  successRedirect: '/',
  failureRedirect: '/signin'
  })
);

app.post('/login', passport.authenticate('local-signin', {
  successRedirect: '/',
  failureRedirect: '/signin'
  })
);


app.get('/auth/twitter', passport.authenticate('twitter'));


app.get('/auth/twitter/callback',
  passport.authenticate('twitter', { failureRedirect: '/signin' }),
  function(req, res) {
    res.redirect('/');
  });




app.get('/logout', function(req, res){
  var name = req.user.username;
  console.log("LOGGIN OUT " + req.user.username)
  req.logout();
  res.redirect('/');
  req.session.notice = "You have successfully been logged out " + name + "!";
});



app.get('/auth/google',
  passport.authenticate('google', { scope: ['openid profile email'] }));


app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/signin' }),
  function(req, res) {
    res.redirect('/');
  });


app.get('/auth/facebook', passport.authenticate('facebook'));

app.get('/auth/facebook/callback',
  passport.authenticate('facebook', { successRedirect: '/',
                                      failureRedirect: '/login' }));


var port = process.argv[2];
app.listen(port, function() {
  console.log('server listening on port ' + port);
});
