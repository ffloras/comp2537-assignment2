const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
require("./utils.js");
require("dotenv").config();

const port = process.env.PORT || 3000;

const app = express();
app.use(express.urlencoded({ extended: true }));
const Joi = require("joi");
const saltRounds = 12;



const expireTime = 60 * 60 * 1000; //expires in 1 hour

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

var { database } = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection("users");

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  crypto: {
    secret: mongodb_session_secret
  }
})


app.use(session(
  {
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true
  }
));

app.use(express.static(__dirname + '/public'));

app.get("/", function (req, res) {
  if (req.session.authenticated) {
    let html = `
    <p>Hello ${req.session.name}!</p>
    <button id='members'>Go to Members Area</button>
    <br>
    <button id='logout'>Log Out</button>
    <script>
      document.getElementById('members').addEventListener('click', (e) => {window.location.replace('/members')});
      document.getElementById('logout').addEventListener('click', (e) => {window.location.replace('/logout')});
    </script>
    `;
    res.send(html);
  } else {
    let html =
      `
    <button id='signup'>Sign Up</button>
    <br>
    <button id='login'>Log In</button>
    <script>
      document.getElementById('signup').addEventListener('click', (e) => {window.location.replace('/signup')});
      document.getElementById('login').addEventListener('click', (e) => {window.location.replace('/login')});
    </script>
    `;
    res.send(html);
  }
});

app.get("/login", function (req, res) {
  let html = `
  <h3>Log In</h3>
  <form action='\loginSubmit' method='post'>
  <input type='email' name='email' placeholder='Email'><br>
  <input type='password' name='password' placeholder='Password'><br>
  <input type='submit' value='Submit'>
  </form>
  `
  res.send(html);
});

app.post("/loginSubmit", async function (req, res) {
  let email = req.body.email;
  let password = req.body.password;

  const schema = Joi.object(
    {
      email: Joi.string().max(30).required(),
      password: Joi.string().max(20).required()
    }
  );

  const validationResult = schema.validate({ email, password });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/login");
    return;
  }

  const result = await userCollection.find({email: email}).project({name: 1, email: 1, password: 1}).toArray();

  if (result.length != 1) {
    let html = `<h3>Email not found.</h3>
    <a href='/login'>Try again</a>
    `;
    res.send(html);
    return;
  } else if (await bcrypt.compare(password, result[0].password)) {
      req.session.authenticated = true;
      req.session.name = result[0].name;
      req.session.cookie.maxAge = expireTime;

      res.redirect("/members");
      return;
  } else {
    let html = `<h3>Incorrect password.</h3>
    <a href='/login'>Try again</a>
    `;
    res.send(html);
    return;
  }

});

app.get("/signup", function (req, res) {
  let html = `
  <h3>Sign up</h3>
  <form action='\signupSubmit' method='post'>
  <input type='text' name='name' placeholder='Name'><br>
  <input type='email' name='email' placeholder='Email'><br>
  <input type='password' name='password' placeholder='Password'><br>
  <input type='submit' value='Submit'>
  </form>
  `
  res.send(html);
});

app.post("/signupSubmit", async function (req, res) {
  let name = req.body.name;
  let email = req.body.email;
  let password = req.body.password;

  let msg = ` is needed.</h3>
  <a href='/signup'>Try again</a>
  `;

  if (name.trim() == "") {
    msg = '<h3>Name' + msg;
    res.send(msg);
  } else if (email.trim() === "") {
    msg = '<h3>Email' + msg;
    res.send(msg);
  } else if (password.trim() === "") {
    msg = '<h3>Password' + msg;
    res.send(msg);
  } else {
    const schema = Joi.object(
      {
        name: Joi.string().alphanum().max(20).required(),
        email: Joi.string().max(30).required(),
        password: Joi.string().max(20).required()
      }
    );

    const validationResult = schema.validate({ name, email, password });
    if (validationResult.error != null) {
      console.log(validationResult.error);
      res.redirect("/signup");
      return;
    }

    let hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({ name: name, email: email, password: hashedPassword });

    req.session.authenticated = true;
    req.session.name = name;
    req.session.cookie.maxAge = expireTime;

    res.redirect("/members");
  }

});

app.get("/members", function (req, res) {
  if (req.session.authenticated) {
    let rand = Math.floor(Math.random() * 3);
    let pic;
    if (rand == 0) {
      pic = "<img src='/giraffe.jpg' style='width:400px;'>";
    } else if (rand == 1) {
      pic = "<img src='/mantis.webp' style='width:400px;'>";
    } else {
      pic = "<img src='/raccoon.jpg' style='width:400px;'>";
    }

    let html = `
    <h1>Hello ${req.session.name}!</h1>
    ${pic}<br>
    <button id='logout'>Sign out</button>
    <script>
      document.getElementById('logout').addEventListener('click', (e) => {window.location.replace('/logout')});
    </script>
    `;
    res.send(html);
  } else {
    res.redirect('/');
  }
  
});

app.get("/logout", function (req, res) {
  if (req.session) {
    req.session.destroy((error) => {
      if (error) {
        res.status(400).send("Unable to log out");
      } else {
        res.redirect("/");
      }
    })
  } else {
    res.redirect("/");
  }
});


app.get("*name", function (req, res) {
  res.status(404);
  res.send("<h1>Page Not Found - 404</h1>");
});


app.listen(port, () => {
  console.log("node application listening on port " + port);
});

//https://comp2537-assignment1-a00982448.onrender.com