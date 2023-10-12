const express = require("express");
const rateLimit = require('express-rate-limit'); //rate-limiter package
const path = require("path");
const app = express();
const port = 3000;
app.use(express.json());
app.use(
  express.urlencoded({
    extended: true,
  })
);
const database = require("./database/database.js"); 
const bcrypt = require('bcrypt'); //bcrypt package



const loginLimiter = rateLimit({ // Defining rate limiter
  windowMs: 10 * 60 * 1000, // 10 minutes then reset
  max: 5, // limiting the user into sending 5 requests per windowMs
  delayMs: 5000, // time of delay is 5 seconds between login attempts
  message: 'Too many login attempts, please try again later.' //appearing msg to user after exceeding the limit
}); 

//
const salt = '$2b$10$C6F86e.BPI1Y.7oFNInVsO'; //generating the salt

app.use('/', express.static(path.join(__dirname, 'public', 'login')));
app.use('/signup', express.static(path.join(__dirname, 'public', 'signup')));

app.post('/login', loginLimiter,  (req, res) => { //changed app.get to app.post + passing loginlimiter to the login request
  const { username, password } = req.body; //changed thr req.query to req.body
  hash = bcrypt.hashSync(password, salt); //hashing the entered password
  const user = {
  username : username,
  password : hash //assigning the password to the hash
  }

   database.authenticate(user)
  .then((result) => {
    if(result.length > 0){
      res.json(result ); 
    }
    else{
      res.redirect('/?error=true');
    }
  }
  )

});

app.post('/submitSignup', (req, res) => { //changed the app.get to app.post
  const { username, password } = req.body; //changed req.query to req.body
  hash = bcrypt.hashSync(password, salt); //hashing the password
 
  const user = {
    username : username,
    password : hash //assigning the password to the hash
  }

  database.signup(user)
  .then((result) => {
    if(result ){
      res.json("user created! please login");
    }
    else{
      res.redirect('/signup?error=true');
    }
  }
  )
});
//
app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});