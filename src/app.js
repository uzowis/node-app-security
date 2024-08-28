const jwt = require('jsonwebtoken');
const path = require('path');
const express = require('express');
const passport = require('passport');
const { Strategy } = require('passport-google-oauth20');
const cookieSession = require('cookie-session');
require('dotenv').config();



const app = express();

app.use(express.json());

const config = {
    CLIENT_ID : process.env.CLIENT_ID,
    CLIENT_SECRET : process.env.CLIENT_SECRET,
    COOKIE_KEY_1 : process.env.COOKIE_KEY_1,
    COOKIE_KEY_2 : process.env.COOKIE_KEY_2,
};
app.use(cookieSession({
    name: 'session',
    keys: [ config.COOKIE_KEY_1, config.COOKIE_KEY_2],
    maxAge: 24 * 60 * 60 * 1000, // expires in 1 day
}));
app.use((req, res, next) => {
    // Stub out missing regenerate and save functions.
    // These don't make sense for client side sessions.
    if (req.session && !req.session.regenerate) {
      req.session.regenerate = (cb) => {
        cb();
      };
    }
    if (req.session && !req.session.save) {
      req.session.save = (cb) => {
        cb();
      };
    }
    next();
  });

const AUTH_OPTIONS = {
    callbackURL : '/auth/google/callback',
    clientID : config.CLIENT_ID,
    clientSecret : config.CLIENT_SECRET

};

function verifyCallback(accessToken, refreshToken, profile, done){
    console.log('Google Profile: ', profile);
    console.log('Access Token : ', accessToken);
    done(null, profile);
}
passport.use(new Strategy(AUTH_OPTIONS, verifyCallback));

app.use(passport.initialize());
app.use(passport.session());



// Write user data (user.id) into the user session
passport.serializeUser((user, done) =>{
    console.log('User details for serialization: ', user);
    done(null, user.id);
});

// Read user ID from the user session
passport.deserializeUser((id, done) =>{
    console.log('User Id: ', id);
    done(null, id );
})

function checkLoggedIn(req, res, next){
    console.log('Current User Details: ', req.user);
    const loggedIn = req.isAuthenticated() && req.user;
    if(!loggedIn) return res.status(401).send('You must Login to access secret!');

    next();
}



/* This generates the JWT token that would be use as authorization (bearer token)
 To access the protected route */

function generateToken(user){
    const payload = {
        id : user.id,
        username : user.username,
    };
    const secret = 'thisismysecretvalue';
    const options = { expiresIn : '1hr'}

    return jwt.sign(payload, secret, options);
}

/*
This function Autheticates users first, if access is granted, a token for the user
is then generated which would be used to access the protected route.
*/
function isLoggedIn(user){
    const username = user.username;
    const id = user.id;

    if(username !== 'Wisdom'){
        return 
    }

    return true;
};

/*
This middleware Is used to decode the token passed into the bearer token, 
if code is valid, the user can access the protected route.
*/
function authenticateToken(req, res, next){
    const token = req.header('Authorization')?.split(' ')[1];   // This returns the bearer

    if(!token) return res.status(401).json({message : 'Access Denied!'});
    
    try {
        const secret = 'thisismysecretvalue';
        const user = jwt.verify(token, secret);
        req.user = user;
        next();
 
    } catch (error) {
        res.status(400).json({error : "Invalid Token!"});
    }
    
  

}

/**********   JWT IMPLEMENTATION ENDPOINTS *********/

// User login endpoint
app.post('/login', (req, res) =>{
    const userData = req.body;
    const user = isLoggedIn(userData);

    if(!user){
        return res.status(401).json({error: 'User not Found!'});
    };
    const token = generateToken(userData);
    return res.status(200).json(token);

});

// Protected endpoint
app.get('/protected', authenticateToken, (req, res) =>{
    res.status(200).send(`<h1>Hey ${req.user.username}, you are successfully authenticated! </h1>`);
});

// root endpoint
app.get('/home', (req, res) => {
    res.status(200).send('<h1>Hey, Welcome to our API endpoint</h1>');
});

/**********   END OF JWT IMPLEMENTATION ENDPOINTS   *********/




app.get('/', (req, res) =>{
    res.status(200).sendFile(path.join(__dirname, '..', 'public', 'index.html'));
})

/**********   OAUTH2.0 SOCIAL SIGN IN IMPLEMENTATION ENDPOINTS *********/

app.get('/auth/google',
     passport.authenticate('google', {
        scope : ['email'],
    }));

app.get('/auth/google/callback', passport.authenticate('google', {
    failureRedirect : '/failure',
    successRedirect : '/secret',
    session : true,
}), (req, res) =>{
        //res.redirect('/secret');
        console.log('Called back by Google');
    });

app.get('/secret', checkLoggedIn, (req, res)=>{
    res.status(200).send(`<h2> Hey, Welcome to your data vault,
         secret code is 002233! </h2>
         </b> 
         <p><a href='auth/logout'>Sign Out</a> <a href='/'>Home</a></p>
         `);
});

app.get('/failure', (req, res)=>{
    res.status(401).send('Login Failed!');
});

app.get('/auth/logout', (req, res, next)=>{
    req.logout((err)=>{
        if(err){
            return next(err);
        }
        res.redirect('/');
    });// this clears the req.user session thereby logging the user out
});







/**********   END OF OAUTH2.0 SOCIAL SIGN IN IMPLEMENTATION ENDPOINTS *********/

module.exports = app;