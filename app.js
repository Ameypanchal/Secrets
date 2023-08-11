//jshint esversion:6
require('dotenv').config();
const express = require('express');
const ejs = require('ejs');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const session = require('express-session')
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
// const encrypt = require('mongoose-encryption');
// const bcrypt = require('bcrypt');
// const saltRounds = 10;

const app = express();
app.set('view engine','ejs')
app.use(express.static('public'));
app.use(bodyParser.urlencoded({extended:true}));
app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(process.env.MONGODB_URI, { useUnifiedTopology: true ,useNewUrlParser: true});

const  userSchema = new mongoose.Schema({
  email:String,
  password:String,
  googleId:String,
  secret:String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);


const User = mongoose.model("User",userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, {
      id: user.id,
      username: user.username,
      picture: user.picture
    });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    // console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/",function(req,res){
  res.render("home")
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

  app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/login",function(req,res){
  res.render("login")
});

app.get("/register",function(req,res){
  res.render("register")
});

app.get("/secrets",function(req,res){
  User.find({"secret":{$ne:null}}).then(function(foundUser){
    if(foundUser){
      res.render("secrets",{userWithsecrets:foundUser})
    }
  });
});

app.get("/logout",function(req,res){
  req.logout(function(err) {
    if (err) { return next(err); }
    res.redirect('/');
  });
});

app.get("/submit",function(req,res){
  if(req.isAuthenticated()){
    res.render("submit")
  }else{
    res.redirect("/login")
  }
});

app.post("/submit",function(req,res){
  const submittedSecret = req.body.secret;
  console.log(req.user);
  User.findById(req.user?.id).then(function(foundUser){
    if(foundUser){
      foundUser.secret = submittedSecret
      foundUser.save().then(function(){res.redirect("/secrets")})
    }
  });
});

app.post("/register",function(req,res){
    User.register({username:req.body.username},req.body.password,function(err,user){
      if(err){
        console.log(err);
        res.redirect("/register")
      }else{
        passport.authenticate("local")(req,res,function(){
          res.redirect("/secrets");
        })
      }
    });

});

app.post("/login",function(req,res){
  const username = req.body.username;
  const password = req.body.password;
  const user = new User({
    username:username,
    password:password
  });

  req.login(user,function(err){
    if(err){
      console.log(err);
    }else{
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      })
    }
  });
});
const PORT = process.env.PORT;
app.listen(PORT,function(){
  console.log("Server running at port 3000");
})
