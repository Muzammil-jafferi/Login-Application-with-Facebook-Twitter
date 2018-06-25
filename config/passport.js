var LocalStrategy   = require('passport-local').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;
var TwitterStrategy = require('passport-twitter').Strategy;
var User       		= require('../app/models/user');

var configAuth = require('./auth');

module.exports = function(passport) {

    passport.serializeUser(function(user, done) {
        done(null, user.id);
    });

    passport.deserializeUser(function(id, done) {
        User.findById(id, function(err, user) {
            done(err, user);
        });
    });


    passport.use('local-login', new LocalStrategy({
        usernameField : 'email',
        passwordField : 'password',
        passReqToCallback : true 
    },
    function(req, email, password, done) { 

        User.findOne({ 'local.email' :  email }, function(err, user) {
            if (err)
                return done(err);

            if (!user)
                return done(null, false, req.flash('loginMessage', 'No user found.')); 

            return done(null, user);
        });

    }));

    passport.use('local-signup', new LocalStrategy({
        usernameField : 'email',
        passwordField : 'password',
        passReqToCallback : true 
    },
    function(req, email, password, done) { 
        var newUser = new User();
        newUser.local.email    = email; 
        newUser.local.password = password; 
                    
        newUser.save(function(err) {
            if (err)
                throw err;

            // if successful, return the new user
            return done(null, newUser);
        });
        
    }));
   
    passport.use(new FacebookStrategy({

        clientID        : configAuth.facebookAuth.clientID,
        clientSecret    : configAuth.facebookAuth.clientSecret,
        callbackURL     : configAuth.facebookAuth.callbackURL
    },
    function(token, refreshToken, profile, done) {
        process.nextTick(function() {
            console.log(profile)
            User.findOne({ 'facebook.id' : profile.id }, function(err, user) {
                if (err)
                    return done(err);

                if (user) {
                    return done(null, user); // user found, return that user
                } else {
                    var newUser            = new User();
                    newUser.facebook.id    = profile.id;                  
                    newUser.facebook.token = token; 
                    var name = profile.displayName.split(" ")
                    newUser.facebook.firstname  = name[0];
                    newUser.facebook.lastname  = name[1]; 
                    //newUser.facebook.email = profile.emails[0].value; 

                    // save our user to the database
                    newUser.save(function(err) {
                        if (err)
                            throw err;

                        // if successful, return the new user
                        return done(null, newUser);
                    });
                }
            });
        });

    }));

    passport.use(new TwitterStrategy({
    
        consumerKey: configAuth.twitterAuth.consumerKey,
        consumerSecret: configAuth.twitterAuth.consumerSecret,
        callbackURL: configAuth.twitterAuth.callbackURL
    },
    function(token, tokenSecret, profile, done) {
        process.nextTick(function() {
               
            User.findOne({ 'twitter.id' : profile.id }, function(err, user) {
                if (err)
                    return done(err);

                if (user) {
                    return done(null, user); // user found, return that user
                } else {
                    var newUser            = new User();
                    newUser.twitter.id    = profile.id; 
                    newUser.twitter.username = profile.username; 
                    newUser.twitter.displayName  = profile.displayName;
                    newUser.twitter.photo  = profile.photos[0].value; 
                    
                    // save our user to the database
                    newUser.save(function(err) {
                        if (err)
                            throw err;

                        // if successful, return the new user
                        return done(null, newUser);
                    });
                }

            });
        });
    }));

};
