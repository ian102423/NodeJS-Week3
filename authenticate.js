const passport = require('passport'); // middleware
const LocalStrategy = require('passport-local').Strategy;
const User = require('./models/user');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const jwt = require('jsonwebtoken'); // used to create, sign, and verify tokens

const config = require('./config.js');

exports.local = passport.use(new LocalStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

exports.getToken = function (user) { // contain user iID for a user document
    return jwt.sign(user, config.secretKey, { expiresIn: 3600 }); // JWT api pass the token as the first item
}; // 3600 === hour

const opts = {};
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
opts.secretOrKey = config.secretKey;

exports.jwtPassport = passport.use(
    new JwtStrategy(
        opts, //
        (jwt_payload, done) => { // verify callback function
            console.log('JWT payload:', jwt_payload);
            User.findOne({ _id: jwt_payload._id }, (err, user) => {
                if (err) {
                    return done(err, false);
                } else if (user) {
                    return done(null, user);
                } else {
                    return done(null, false);
                }
            });
        }
    )
);

exports.verifyUser = passport.authenticate('jwt', { session: false });