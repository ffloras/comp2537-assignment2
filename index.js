const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
require("./utils.js");
require("dotenv").config();
const { ObjectId } = require('mongodb');
const URL = require("url").URL;

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

app.set('view engine', 'ejs');

app.use(session(
  {
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true
  }
));

app.use(express.static(__dirname + '/public'));

imgLinks = ['/giraffe.jpg', '/mantis.webp', 'raccoon.jpg'];

navLinks = [
  {name: "Home", url: "/", svg: "#home"},
  {name: "Log In", url: "/login", svg: "#grid"},
  {name: "Sign Up", url: "/signup", svg: "#collection"},
  {name: "Members", url: "/members", svg: "#sun-fill"},
  {name: "Admin", url: "/admin", svg: "#people-circle"},
  {name: "Log Out", url: "/logout", svg: "#grid"}
]

app.use("/", (req, res, next) => {
  app.locals.imgLinks = imgLinks;
  app.locals.navLinks = navLinks;
  let fullUrl = req.protocol + '://' + req.get('host') + req.originalUrl;
  let folder = new URL(fullUrl).pathname.split('/').slice(1);
  app.locals.currentURL = '/' + folder[0];
  next();
});

function sessionAuthentication(req, res, next) {
  if (req.session.authenticated) {
    next();
  } else {
    res.redirect("/login");
  }
}

function sessionAuthorization(req, res, next) {
  if (req.session.user_type === "admin") {
    next();
  } else {
    res.status(403);
    res.render("admin", {heading: "403 - Authorization required", users: []});
  }
}

app.get("/", function (req, res) {
  if (req.session.authenticated) {
    let info = {
      btn1: "Go to Member's Area", 
      btn2: "Logout", 
      heading: `Hello, ${req.session.name}!`,
      urls: ['/members', '/logout']
    }
    res.render("index", info);
  } else {
    let info = {
      btn1: "Sign Up",
      btn2: "Log in",
      heading: "",
      urls: ['/signup', '/login']
    }
    res.render("index", info);
  }
});

app.get("/login", function (req, res) {
  res.render("login");
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

  const result = await userCollection.find({email: email})
  .project({name: 1, email: 1, password: 1, user_type: 1, _id: 1}).toArray();

  if (result.length != 1) {
    res.render("loginSubmit", {prompt: "Email not found"});
    return;
  } else if (await bcrypt.compare(password, result[0].password)) {
      req.session.authenticated = true;
      req.session.name = result[0].name;
      req.session.user_type = result[0].user_type
      req.session.cookie.maxAge = expireTime;
      req.session.id = result[0]._id;

      res.redirect("/members");
      return;
  } else {
    res.render("loginSubmit", {prompt: "Incorrect Password"});
    return;
  }

});

app.get("/signup", function (req, res) {
  res.render("signup");
});

app.post("/signupSubmit", async function (req, res) {
  let name = req.body.name;
  let email = req.body.email;
  let password = req.body.password;

  if (name.trim() == "") {
    res.render("signupSubmit", {prompt: "Name"});
  } else if (email.trim() === "") {
    res.render("signupSubmit", {prompt: "Email"});
  } else if (password.trim() === "") {
    res.render("signupSubmit", {prompt: "Password"});
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

    await userCollection.insertOne({ name: name, email: email, password: hashedPassword, user_type: "user" });

    req.session.authenticated = true;
    req.session.name = name;
    req.session.user_type = "user";
    req.session.cookie.maxAge = expireTime;

    res.redirect("/members");
  }

});

app.use("/members", sessionAuthentication);
app.get("/members", function (req, res) {
    res.render('members', {name: req.session.name});
});

app.use("/admin", sessionAuthentication, sessionAuthorization);
app.get("/admin", async function (req, res) {
  let user = req.query.user;
  let type = req.query.type;
  if (user && type) {
    let id = new ObjectId(user);
    await userCollection.updateOne({_id: id}, {$set: {user_type: type}});
  }
  let result = await userCollection.find().project({name: 1, user_type: 1, _id: 1}).toArray();
  res.render("admin", {heading: "Users", users: result});
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
  res.render("404");
});


app.listen(port, () => {
  console.log("node application listening on port " + port);
});

//https://comp2537-assignment1-a00982448.onrender.com