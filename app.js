require("dotenv").config();
const express = require("express");
const app = express();
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const flash = require("connect-flash");
const bodyParser = require("body-parser");
const User = require("./models/user.js");
const bcrypt = require("bcrypt");
const saltRounds = 10;

app.set("view engine", "ejs");
app.use(cookieParser(process.env.SECERT));
app.use(
  session({
    secret: process.env.SECERT,
    resave: false,
    saveUninitialized: false,
  })
);
app.use(flash());
app.use(bodyParser.urlencoded({ extended: true }));

// a middleware to handle whether the user has login to see the secret
const requireLogin = (req, res, next) => {
  if (!req.session.isVerified) {
    res.redirect("/login");
  } else {
    next();
  }
};

mongoose
  .connect("mongodb://127.0.0.1:27017/test", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("Connected to MongoDB.");
  })
  .catch((e) => {
    console.log(e);
  });

app.get("/", (req, res) => {
  res.send("Home page");
});

app.get("/secret", requireLogin, (req, res) => {
  res.render("secret.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.post("/login", async (req, res, next) => {
  let { username, password } = req.body;

  try {
    let foundUser = await User.findOne({ username });
    if (foundUser) {
      bcrypt.compare(password, foundUser.password, (err, result) => {
        if (err) {
          next(err);
        }

        if (result == true) {
          req.session.isVerified = true;
          res.redirect("/secret");
        } else {
          res.send("Username or password is incorrect.");
        }
      });
    } else {
      res.send("Username or password is incorrect.");
    }
  } catch (e) {
    next(e);
  }
});

app.get("/signup", (req, res) => {
  res.render("signup.ejs");
});

app.post("/signup", async (req, res, next) => {
  let { username, password } = req.body;
  try {
    let foundUser = await User.findOne({ username });
    if (foundUser) {
      res.send("Username is already in use. Select another username.");
    } else {
      bcrypt.genSalt(saltRounds, (err, salt) => {
        if (err) {
          next(err);
        }

        bcrypt.hash(password, salt, (err, hash) => {
          if (err) {
            next(err);
          }

          let newUser = new User({ username, password: hash });
          try {
            newUser
              .save()
              .then(() => {
                res.send("Data has been saved.");
              })
              .catch((e) => {
                res.send("Error!");
              });
          } catch (err) {
            next(err);
          }
        });
      });
    }
  } catch (err) {
    next(err);
  }
});

app.get("/*", (req, res) => {
  res.status(404).send("404 page not found.");
});

// error handler
app.use((err, req, res, next) => {
  console.log(err);
  res.status(500).send("Something is broken. We will fix it soon.");
});

app.listen(3000, () => {
  console.log("Server is running on port 3000.");
});
