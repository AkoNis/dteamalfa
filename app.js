var express = require('express');
var path = require('path');
var favicon = require('static-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var session = require('express-session')
var mongoose = require('mongoose');
var nodemailer = require('nodemailer');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var bcrypt = require('bcrypt-nodejs');
var async = require('async');
var crypto = require('crypto');
var flash = require('express-flash');
var http = require('http').Server(app);


passport.use(new LocalStrategy(function(username, password, done) {
  User.findOne({ username: username }, function(err, user) {
    if (err) return done(err);  
    if (!user) return done(null, false, { message: 'Incorrect username.' });
    user.comparePassword(password, function(err, isMatch) {
      if (isMatch) {
        return done(null, user);
      } else {
        return done(null, false, { message: 'Incorrect password.' });
      }
    });
  });
}));

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

var userSchema = mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  resetPasswordToken: String,
  resetPasswordExpires: Date
});

var orderSchema = mongoose.Schema({
  _id: String,
  order_id: String,
  status: Number,
  owner: String,
  DATE: String
});

userSchema.pre('save', function(next) {
  var user = this;
  var SALT_FACTOR = 5;

  if (!user.isModified('password')) return next();

  bcrypt.genSalt(SALT_FACTOR, function(err, salt) {
    if (err) return next(err);

    bcrypt.hash(user.password, salt, null, function(err, hash) {
      if (err) return next(err);
      user.password = hash;
      next();
    });
  });
});

userSchema.methods.comparePassword = function(candidatePassword, cb) {
  bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
    if (err) return cb(err);
    cb(null, isMatch);
  });
};
var db = mongoose.connect('mongodb://dreamteam:kappa123@ds137340.mlab.com:37340/dreamteam');

var User = db.model('users', userSchema);
var Order = db.model('orders', orderSchema);

var app = express();

// Middleware
app.set('port', process.env.PORT || 3000);
app.set('views', path.join(__dirname, 'views'));
app.set('view engine','jade');
app.use(favicon());
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded());
app.use(cookieParser());
app.use(session({ secret: 'session secret key' }));
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static(path.join(__dirname, '/public')));

app.use("/styles",express.static(__dirname + "/public/stylesheets/"));


// If val 1, members only
function membersOnly(req, res, val) {
  if (val == 1) {
    if (req.user) {
      // logged in
    } else {
      // not logged in
      return res.redirect('/login');
    }
  } 
  if (val == 0) {
    if (!req.user) {
      // not logged
    } else {
      // logged in
      return res.redirect('/');
    }
  }
}


// Routes
app.get('/', function(req, res) {
  membersOnly(req, res, 1);
  res.render('index', {username: req.user.username});
  
  io.on('connection', function(socket){
    console.log('a user connected');

    console.log("This user logged in: " + req.user.username);
    
    
    var currentUser = req.user.username;
    //All
    Order.count({owner: currentUser, status : 0}, function(err, c) {
           console.log('Processed orders: ' + c);
           var Processed = c;
           setInterval(function(){
           socket.emit('process', Processed);
           }, 1000);
      });
    Order.count({owner: currentUser, status : 2}, function(err, c) {
           console.log('Fulfilled orders: ' + c);
           var Fulfilled = c;
           setInterval(function(){
           socket.emit('fulfill', Fulfilled);
           }, 1000);
      });
    Order.count({owner: currentUser, status : 3}, function(err, c) {
           console.log('Failed orders: ' + c);
           var Failed = c;
           setInterval(function(){
           socket.emit('failed', Failed);
           }, 1000);
      });

    //Day
    Order.count({owner: currentUser, status : 0, DATE : {$gte: "2017-05-07" }}, function(err, c) {
           console.log('Processed orders: ' + c);
           var Processed = c;
           setInterval(function(){
           socket.emit('processDay', Processed);
           }, 1000);
      });
    Order.count({owner: currentUser, status : 2,DATE : {$gte: "2017-05-07" }}, function(err, c) {
           console.log('Fulfilled orders: ' + c);
           var Fulfilled = c;
           setInterval(function(){
           socket.emit('fulfillDay', Fulfilled);
           }, 1000);
      });
    Order.count({owner: currentUser, status : 3, DATE : {$gte: "2017-05-07" }}, function(err, c) {
           console.log('Failed orders: ' + c);
           var Failed = c;
           setInterval(function(){
           socket.emit('failedDay', Failed);
           }, 1000);
      });

    //Week
    Order.count({owner: currentUser, status : 0, DATE :{ $gte : "2017-05-00" , $lte: "2017-05-07" }}, function(err, c) {
           console.log('Processed orders: ' + c);
           var Processed = c;
           setInterval(function(){
           socket.emit('processWeek', Processed);
           }, 1000);
      });
    Order.count({owner: currentUser, status : 2,DATE :{ $gte : "2017-05-00", $lte: "2017-05-07" }}, function(err, c) {
           console.log('Fulfilled orders: ' + c);
           var Fulfilled = c;
           setInterval(function(){
           socket.emit('fulfillWeek', Fulfilled);
           }, 1000);
      });
    Order.count({owner: currentUser, status : 3, DATE :{ $gte : "2017-05-00", $lte: "2017-05-07" }}, function(err, c) {
           console.log('Failed orders: ' + c);
           var Failed = c;
           setInterval(function(){
           socket.emit('failedWeek', Failed);
           }, 1000);
      });
    
    //Month
    Order.count({owner: currentUser, status : 0, DATE :{ $gt : "2017-04-00"}}, function(err, c) {
           console.log('Processed orders: ' + c);
           var Processed = c;
           setInterval(function(){
           socket.emit('processMonth', Processed);
           }, 1000);
      });
    Order.count({owner: currentUser, status : 2,DATE :{ $gt : "2017-04-00"}}, function(err, c) {
           console.log('Fulfilled orders: ' + c);
           var Fulfilled = c;
           setInterval(function(){
           socket.emit('fulfillMonth', Fulfilled);
           }, 1000);
      });
    Order.count({owner: currentUser, status : 3, DATE :{ $gt : "2017-04-00"}}, function(err, c) {
           console.log('Failed orders: ' + c);
           var Failed = c;
           setInterval(function(){
           socket.emit('failedMonth', Failed);
           }, 1000);
      });
    });
  });





app.get('/404', function(req, res){
   res.render('not404', { title: 'Express' });
});


//Index (Homepages)
app.get('/', function(req, res) {
  res.render('index', {
    title: 'Express',
    user: req.user
  });
  
});

//Login
app.get('/login', function(req, res) {
  membersOnly(req, res, 0);
  res.render('login', {
    user: req.user
  });
});

//forgot-password
app.get('/forgot-password', function(req, res) {
  res.render('forgot', {
    user: req.user
  });
});

app.get('/reset-password', function(req, res) {
  res.render('reset', {
    user: req.user
  });
});

app.post('/login', function(req, res, next) {
  passport.authenticate('local', function(err, user, info) {
    if (err) return next(err)
    if (!user) {
      return res.redirect('/login')
    }
    req.logIn(user, function(err) {
      if (err) return next(err);
      return res.redirect('/');
    });
  })(req, res, next);
});

//Sign up
app.get('/signup', function(req, res){
  membersOnly(req, res, 0);
	res.render('signup', {
		user:req.user
	});
});

app.post('/signup', function(req, res){
	var user = new User({
		username: req.body.username,
		email: req.body.email,
		password: req.body.password
	});
	user.save(function(err){
		req.logIn(user, function(err){
			res.redirect('/');
		});
	});
});

//Logout
app.get('/logout', function(req, res){
	req.logout();
	res.redirect('/');
});


//Forgot Password

app.post('/forgot-password', function(req, res, next) {
  async.waterfall([
    function(done) {
      crypto.randomBytes(20, function(err, buf) {
        var token = buf.toString('hex');
        done(err, token);
      });
    },
    function(token, done) {
      User.findOne({ email: req.body.email }, function(err, user) {
        if (!user) {
          req.flash('error', 'No account with that email address exists.');
          return res.redirect('/forgot-password');
        }

        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

        user.save(function(err) {
          done(err, token, user);
        });
      });
    },
    function(token, user, done) {
      var smtpTransport = nodemailer.createTransport({
        service: 'Gmail',
        auth: {
          user: 'dteam163@gmail.com',
          pass: 'Gabbe163'
        }
      });
      var mailOptions = {
        to: user.email,
        from: 'dteam163@gmail.com',
        subject: 'Node.js Password Reset',
        text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
          'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
          'http://' + req.headers.host + '/reset/' + token + '\n\n' +
          'If you did not request this, please ignore this email and your password will remain unchanged.\n'
      };
      smtpTransport.sendMail(mailOptions, function(err) {
        done(err, 'done');
      });
      res.redirect('/login');
    }
  ], function(err) {
    if (err) return next(err);
    res.redirect('/forgot-password');
  });
});

app.get('/reset/:token', function(req, res) {
  User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
    if (!user) {
      req.flash('error', 'Password reset token is invalid or has expired.');
      return res.redirect('/forgot-password');
    }
    res.render('reset', {
      user: req.user
    });
  });
});

app.post('/reset/:token', function(req, res) {
  async.waterfall([
    function(done) {
      User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
        if (!user) {
          req.flash('error', 'Password reset token is invalid or has expired.');
          return res.redirect('back');
        }

        user.password = req.body.password;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;

        user.save(function(err) {
          req.logIn(user, function(err) {
            done(err, user);
          });
        });
      });
    },
    function(user, done) {
      var smtpTransport = nodemailer.createTransport( {
        service: 'Gmail',
        auth: {
          user: 'dteam163@gmail.com',
          pass: 'Gabbe163'
        }
      });
      var mailOptions = {
        to: user.email,
        from: 'dteam163@gmail.com',
        subject: 'Your password has been changed',
        text: 'Hello,\n\n' +
          'This is a confirmation that the password for your account ' + user.email + ' has just been changed.\n'
      };
      smtpTransport.sendMail(mailOptions, function(err) {
        done(err);
      });
      res.redirect('/login')
    }
  ], function(err) {
    res.redirect('/');
  });
});



app.get('*', function(req, res){
    res.redirect('/404');
});


app.listen(app.get('port'), function() {
  console.log('Express server listening on port ' + app.get('port'));
});

var io = require('socket.io').listen(3001);