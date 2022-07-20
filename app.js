require('dotenv').config();
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const LocalStrategy = require("passport-local").Strategy;
const encrypt = require("mongoose-encryption");
const session = require("express-session");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const passport = require("passport");
const express = require("express");
const bcrypt = require("bcrypt");
const ejs = require("ejs");
const md5 = require("md5");

// Setup Server
const app = express();
app.set('view engine', 'ejs');
app.use(express.static(__dirname + "/public"));
app.use(express.urlencoded({extended: true}));

// Passport & Session Configuration
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

// MongoDB Connection & Model
mongoose.connect(process.env.DB_CONNECTION_STRING);
const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true
    },
    password: String,
    googleId: String,
    facebookId: String,
    secrets: [String]
});

// Database Encryption
// userSchema.plugin(encrypt, { 
//     secret: process.env.SECRET_KEY,
//     encryptFields: ['password'],
//     excludeFromEncryption: ['email']
// });
const User = new mongoose.model("User", userSchema);

// Passport Strategy, Serialize & Deserialize Users
passport.use(new LocalStrategy(
    {
        usernameField: "username",
        passwordField: "password"
    }, 
    (username, password, done) => {
        User.findOne({ email: username }, async (error, foundUser) => {
            if (error) {
                return done(error);
            } else {
                if (!foundUser) {
                    return done(null, false, { message: "No User Found" });
                } else {
                    try {
                        if (await bcrypt.compare(password, foundUser.password)) {
                            return done(null, foundUser);
                        } else {
                            return done(null, false, { message: "Invalid Password" });
                        }
                    } catch(e) {
                        return done(e);
                    }
                }
            }
        });
    }
));

passport.use(new GoogleStrategy(
    {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "https://whispering-mesa-15829.herokuapp.com/auth/google/secrets",
        scope: ["profile", "email"]
    },
    (accessToken, refreshToken, profile, done) => {
        User.findOne({ googleId: profile.id }, (error, foundUser) => {
            if (error) {
                return done(error);
            } else {
                if (!foundUser) {
                    const newUser = new User({
                        email: profile.emails[0].value,
                        googleId: profile.id
                    });
                    newUser.save((err) => {
                        if (err) {
                            return done(err);
                        } else {
                            return done(null, newUser);
                        }
                    });
                } else {
                    return done(null, foundUser);
                }
            }
        });
    }
));

passport.use(new FacebookStrategy(
    {
        clientID: process.env.FACEBOOK_APP_ID,
        clientSecret: process.env.FACEBOOK_APP_SECRET,
        callbackURL: "https://whispering-mesa-15829.herokuapp.com/auth/facebook/secrets",
        profileFields: ["id", "email", "name"]
    },
    (accessToken, refreshToken, profile, done) => {
        User.findOne({ facebookId: profile.id }, (error, foundUser) => {
            if (error) {
                return done(error);
            } else {
                if (!foundUser) {
                    const newUser = new User({
                        email: profile.emails[0].value,
                        facebookId: profile.id
                    });
                    newUser.save((err) => {
                        if (err) {
                            return done(err);
                        } else {
                            return done(null, newUser);
                        }
                    });
                } else {
                    return done(null, foundUser);
                }
            }
        });
    }
));

passport.serializeUser((user, done) => {
    done(null, user._id);
});

passport.deserializeUser((userID, done) => {
    User.findById(userID, (error, foundUser) => {
        if (error) {
            return done(error);
        } else {
            if (foundUser) {
                done(null, foundUser);
            } else {
                done(null, false);
            }
        }
    });
});

// GET Requests
app.get("/", checkIfAuthenticated, (req, res) => {
    res.render("home");
});

app.get("/register", checkIfAuthenticated, (req, res) => {
    res.render("register");
});

app.get("/login", checkIfAuthenticated, (req, res) => {
    res.render("login");
});

app.get("/auth/google", passport.authenticate("google", { 
    scope: ["profile", "email"] 
}));

app.get("/auth/facebook", passport.authenticate("facebook", { 
    scope: ["email"] 
}));

app.get("/auth/google/secrets", passport.authenticate("google", {
    scope: ["profile", "email"],
    successRedirect: "/secrets",
    failureRedirect: "/login"
}));

app.get("/auth/facebook/secrets", passport.authenticate("facebook", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
    scope: ["email"]
}));

app.get("/secrets", checkNotAuthenticated, (req, res) => {
    User.find({ secrets: {$exists: true, $not: {$size: 0}} }, (error, foundUsers) => {
        if (error) {
            console.log(error);
            res.send(error);
        } else {
            res.render("secrets", {
                usersWithSecrets: foundUsers
            });
        }    
    });
});

app.get("/submit", checkNotAuthenticated, (req, res) => {
    res.render("submit");
});

// POST Requests
const saltRounds = 10;
app.post("/register", async (req, res) => {
    try {
        await bcrypt.hash(req.body.password, saltRounds, (err, hash) => {
            const newUser = new User({
                email: req.body.username,
                password: hash
            });
            newUser.save((error) => {
                if (error) {
                    console.log(error);
                } else {
                    res.redirect("/login");
                }
            });
        });
    } catch(e) {
        console.log(e);
    }
});

app.post("/login", passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login"
}));

app.post("/submit", (req, res) => {
    User.findById(req.user._id, (error, foundUser) => {
        if (error) {
            console.log(error);
            res.redirect("/submit");
        } else {
            if (foundUser) {
                foundUser.secrets.push(req.body.secretText);
                foundUser.save((error) => {
                    if (error) {
                        console.log(error);
                    } else {
                        res.redirect("/secrets");
                    }
                });
            }
        }
    });
});

app.post("/logout", async (req, res) => {
    await req.logout((error) => {
        if (error) {
            console.log(error);
        } else {
            res.redirect("/");
        }
    });
});

// Helper Middlewares
function checkIfAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        res.redirect("/secrets");
        return;
    }
    next();
}

function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect("/login");
}

// Start Server
let port = process.env.PORT;
if (port == null || port == "") { port = 3000; };
app.listen(port, () => {
    console.log("Server Started Successfully!");
});