var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var User = require('./models/user');
var JwtStrategy = require('passport-jwt').Strategy;
var ExtractJwt = require('passport-jwt').ExtractJwt;
var jwt = require('jsonwebtoken'); // used to create, sign, and verify tokens

var config = require('./config');
// authenticte => req.user property is mounted to the request message
exports.local = passport.use(new LocalStrategy(User.authenticate())); 
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

exports.getToken = function (user) {
    return jwt.sign(user, config.secretKey, //create the jsonwebtoken
        { expiresIn: 3600 });
};
// configure jwt strategy for our passport application
var opts = {}; //options to specify for my jwt based strategy
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken(); // how the token should be extracted from the incoming request message
opts.secretOrKey = config.secretKey; // used within my strategy for the sign in
//when passport parses the req mess it will use strategy and extract information and load on req mess
exports.jwtPassport = passport.use(new JwtStrategy(opts,
    (jwt_payload, done) => { // DONE using for loading thing into the req mess
        console.log("JWT payload: ", jwt_payload);
        User.findOne({ _id: jwt_payload._id }, (err, user) => {
            if (err) {
                return done(err, false);
            }
            else if (user) {
                return done(null, user);
            }
            else {
                return done(null, false);
            }
        });
    }));

exports.verifyUser = passport.authenticate('jwt', { session: false });

exports.verifyAdmin = function (req, res, next) {
    if (!req.user.admin) {
        var err = new Error('You are not authorized to perform this operation!');
        err.status = 403;
        return next(err);        
    } 
    next();
};