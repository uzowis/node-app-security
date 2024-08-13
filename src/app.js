const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();

app.use(express.json());


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
app.get('/', (req, res) => {
    res.status(200).send('<h1>Hey, Welcome to our API endpoint</h1>');
});





module.exports = app;