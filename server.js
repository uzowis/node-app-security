const fs = require('fs');
const https = require('https');
const helmet = require('helmet');
require('dotenv').config();


// Import the core express application
const app = require('./src/app');

// Middlewares
app.use(helmet());
app.disable('x-powered-by');


const PORT = process.env.PORT || 8000;
const httpsOptions = {
    key : fs.readFileSync('key.pem'),
    cert : fs.readFileSync('cert.pem'),
};
const server = https.createServer(httpsOptions, app);



// Start Server in Https 
server.listen(PORT, () =>{
    console.log(`Server Listening at Port ${PORT}`);

});