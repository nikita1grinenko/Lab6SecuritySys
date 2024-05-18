const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const jwt = require('jsonwebtoken')
const axios = require('axios')
const port = 3000;
const jwksClient = require('jwks-rsa');
const session = require('express-session');

const app = express();
app.use(session({
    secret: 'your_secret_key', // Секретний ключ для підпису cookie
    resave: false, // Чи перезберігати сесію при кожному запиті
    saveUninitialized: true // Чи зберігати сесію для нових, не ініціалізованих запитів
}));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const AUTH_HEADER = 'authorization';

const CLIENT_ID = 'HmyoofaoL8mhp3gyBHGdMqlQANiqpc0s';
const CLIENT_SECRET = 'jTfD9KYUxiW35bl6Nm6RC0Njx3gHrDYAJtIwIrrXsIZEO5depFk4oFeuLGfp6usI';
const AUDIENCE = 'https://dev-iok04fd4rdabjfsd.eu.auth0.com/api/v2/';
const DOMAIN = 'https://dev-iok04fd4rdabjfsd.eu.auth0.com';
login = false;

app.use(async (req, res, next) => {
    //const token = req.headers[AUTH_HEADER];
    const token = req.session.token;

    if (token?.length) {
        var client = jwksClient({
            jwksUri: 'https://dev-iok04fd4rdabjfsd.eu.auth0.com/.well-known/jwks.json'
        });

        function getKey(header, callback) {
            client.getSigningKey(header.kid, function (err, key) {
                var signingKey = key.publicKey || key.rsaPublicKey;
                callback(null, signingKey);
            });
        }

        try {
            jwt.verify(token, getKey, function (err, decoded) {
                if (err) {
                    console.error(err);
                    return next();
                }
                //console.log('decoded', decoded);
                req.session.data = decoded; // Set session inside the callback
                console.log(req.session.data); // Now session should be defined
                next(); // Move next() inside the callback
            });
        } catch (e) {
            console.log(e);
            next();
        }
    } else {
        next();
    }
});

app.get('/', (req, res) => {
    if (req.session?.token) {
        login = false;

        return res.json({
            username: req.session.data.email,
            logout: 'http://localhost:3000/logout'
        })
    }

    const redirect_uri = encodeURIComponent('http://localhost:3000/callback');

    res.redirect(DOMAIN + '/authorize?client_id=' +
        CLIENT_ID + '&redirect_uri=' + redirect_uri +
        '&response_type=code&response_mode=query' +
        '&scope=openid%20email'
    );


});

app.get('/callback', (req, res) => {
    const {code} = req.query;
    console.log(code);

    axios({
        method: 'post',
        url: 'https://dev-iok04fd4rdabjfsd.eu.auth0.com/oauth/token',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        data: {
            grant_type: 'authorization_code',
            code: code,
            redirect_uri: 'http://localhost:3000/callback',
            scope: 'offline_access',
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET
        }
    })
        .then(response => {
            console.log(response.data);
            //const session = sessionStorage.getItem('session');
            const {id_token} = response.data;
            console.log(id_token);
            req.session.token = id_token;
            login = true;
            res.redirect('/');
        })
        .catch(e =>{
            console.error(e.message);
            res.status(401).send(e.message);
        });
});

app.get('/logout', (req, res) => {
    req.session.token = undefined;
    req.session.data = undefined;

    res.redirect('/');
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})
