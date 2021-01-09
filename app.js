//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended:true
}));

// tell app to use the package and sets it up
app.use(session({
  secret: "I got secret secret formula",
  resave: false,
  saveUninitialized: false
}));

// tell app to use passport to initialize package and to use passport to deal with sessions
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
    username: { type: String, unique: true }, // values: email address, googleId, facebookId
    password: String,
    provider: String, // values: 'local', 'google', 'facebook'
    email: String,
    secret: String
});

//used to hash and salt passwords and save users into mongoDB
userSchema.plugin(passportLocalMongoose, {
  usernameField: "username"
});
// enables passport's findOrCreate function
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

// authenticates users using usernames and passwords
passport.use(User.createStrategy());

// creates and destroys cookie containing message
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

// google configuration
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ username: profile.id }, { provider: "google", email: profile._json.email }, function (err, user) {
        return cb(err, user);
    });
  }
));

// facebook configuration
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets",
    profileFields: ["id", "email"]
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ username: profile.id }, { provider: "facebook", email: profile._json.email }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res){
  res.render("home");
});

//google authenticate
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get("/auth/google/secrets", passport.authenticate("google", { failureRedirect: "/login" }), function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
});

//facebook authenticate
app.get('/auth/facebook', passport.authenticate('facebook', { scope: ["email"]
})
);

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/login", function(req, res){
  res.render("login");
});

app.route('/register')
    .get(function(req, res) {
        res.render('register');
    })
    .post(function(req, res) {
        const username = req.body.username;
        const password = req.body.password;

        User.register({username: username}, password, function(err, user) {
          if (err) {
            console.log(err);
            res.redirect('/register');
          } else {
            passport.authenticate('local')(req, res, function() {
              User.updateOne(
                { _id: user._id },
                { $set: { provider: "local", email: username } },
                function() {
                  res.redirect('/secrets');
                }
              );
            });
          }
        });
    });

app.get("/secrets", function(req, res){
  User.find({"secret": {$ne: null}}, function(err, foundUsers){
    if (err){
      console.log(err);
    } else {
      if (foundUsers) {
        res.render("secrets", {usersWithSecrets: foundUsers});
      }
    }
  });
});

app.get("/submit", function(req, res){
  if (req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;

  console.log(req.user);

  User.findById(req.user.id, function(err, foundUser){
    if (err){
      console.log(err);
    } else {
      foundUser.secret = submittedSecret;
      foundUser.save(function(){
        res.redirect("/secrets");
      });
    }
  });
});

app.get("/logout", function(req, res){
  req.logout();
  res.redirect("/");
});

app.post("/login", function(req, res){

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });
  //use passport to login and authenticate user
  req.login(user, function(err){
    if (err){
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });
});

app.listen(3000, function(){
  console.log(("Server started on port 3000"));
});
