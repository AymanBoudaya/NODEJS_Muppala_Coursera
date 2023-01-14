var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var User = require('./models/user');
const bodyParser = require('body-parser');

var JwtStrategy = require('passport-jwt').Strategy;
var ExtractJwt = require('passport-jwt').ExtractJwt;
var jwt = require('jsonwebtoken'); // used to create, sign, and verify tokens

var config = require('./config');
const { authenticate } = require('passport');

exports.local = passport.use(new LocalStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

exports.getToken = function (user) {
    return jwt.sign(user, config.secretKey,
        { expiresIn: 3600 });
};

var opts = {};
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
opts.secretOrKey = config.secretKey;

exports.jwtPassport = passport.use(new JwtStrategy(opts,
    (jwt_payload, done) => {
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



exports.verifyOrdinaryUser = function (req, res, next) {
    //     check header or url parameters or post parameters for token
         var anyToken = req.headers.authorization || req.body.token || req.query.token;
         console.log("anytoken : ", anyToken);
         const extractToken = anyToken.split(" ")[1];
         // decode token
         if (anyToken) {
             // verifies secret and checks exp
             jwt.verify(extractToken, config.secretKey, function (err, decoded) {
                 if (err) {
                     var err = new Error('You are not authenticated!');
                     err.status = 401;
                     return next(err);
                 } else {
                     // if everything is good, save to request for use in other routes
                     req.decoded = jwt.decode(extractToken);
                     next();
                 }
             });
         } else {
             // if there is no token
             // return an error
             var err = new Error('No token provided!');
             err.status = 403;
             return next(err);
         }
     };

exports.verifyAdmin = function (req, res, next) {
    
    if (!req.decoded.admin) {
        return res.status(403).send('access rejected...')
    } 
    next();

};