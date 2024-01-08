require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate')

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
secret: "our little master here",
resave: false,
saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(`${process.env.URL}`);
// mongoose.set("useCreateIndex", true); // just to play safe side for deprecation error 12:57, and by default it is set to tru in Mongoose version 5 and above

const userSchema = new mongoose.Schema ({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

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
    callbackURL: "https://secrets-la4e.onrender.com/auth/google/secrets",
    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);

    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get("/", function(req, res){
    res.render("home");
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] })
  );

  app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/login", function(req, res){
    res.render("login");
});

app.get("/register", function(req, res){
    res.render("register");
});

app.get("/secrets", function(req, res) {
    if (req.isAuthenticated()) {
        // User is authenticated, retrieve and render secrets
        User.find({"secret": {$ne: null}})
            .then(foundUsers => {
                if (foundUsers && foundUsers.length > 0) {
                    res.render("secrets", {usersWithSecrets: foundUsers});
                } else {
                    // No users with non-null secrets found
                    res.render("no-secrets");
                }
            })
            .catch(err => {
                console.error(err);
                res.status(500).send("Internal Server Error");
            });
    } else {
        // User is not authenticated, redirect to login
        res.redirect("/login");
    }
});




app.get("/submit", function(req, res){
    if (req.isAuthenticated()){
        res.render("submit");
    } else {
        res.redirect("/login");
    }  
});

app.post("/submit", function(req, res) {
    const submittedSecret = req.body.secret;

    console.log(req.user.id);

    User.findById(req.user.id)
    .exec()
    .then(foundUser => {
        if (foundUser) {
            foundUser.secret = submittedSecret;
            return foundUser.save();
        } else {
            console.log("User not found");
            return null; // or handle the error case accordingly
        }
    })
    .then(() => {
        res.redirect("/secrets");
    })
    .catch(err => {
        console.error(err);
        // Handle the error appropriately
    });

});

app.post("/register", function(req, res){

    User.register({username: req.body.username}, req.body.password, function(err, user){
        if (err) {
            console.log(err);
            res.redirect("/register");
    }else {
        passport.authenticate("local")(req, res, function(){
            res.redirect("/secrets");
        });
    }
    });
  
});

app.post("/login", async function(req, res) {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function(err){ //this method comes passport documentation
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
    });
    
});

app.get("/logout", function(req, res,next){

    // res.redirect("/secrets"); // this only redirects previous session is still accessible

    // This logout deletes the session history taken from offical passportjs docs : https://www.passportjs.org/tutorials/password/logout/
    req.logout(function(err) {
        if (err) { return next(err); }
        res.redirect('/');
      });
    });



app.listen(3000, function() {
    console.log("Server is running on http://localhost:3000/");
});