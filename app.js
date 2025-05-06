/** @format */

import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import session from "express-session";
import passport from "passport";
import {Strategy} from "passport-local";
import bcrypt from "bcrypt";
import dotenv from "dotenv";

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Set up bcrypt
const saltRounds = 10;

// Set up the view engine
app.set("view engine", "ejs");
app.set("views", "views");

// Set up middleware
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

app.use(
	session({
		secret: process.env.SESSION_SECRET,
		resave: false,
		saveUninitialized: true,
		cookie: {
			maxAge: 1000 * 60 * 60 * 24 * 7,
		},
	})
);

app.use(passport.initialize());
app.use(passport.session());

// Set up the database
const db = new pg.Client({
	user: process.env.DB_USER,
	host: process.env.DB_HOST,
	database: process.env.DB_NAME,
	password: process.env.DB_PASSWORD,
	port: process.env.DB_PORT,
});
db.connect();

// Update the root route to check authentication
app.get("/", (req, res) => {
	if (req.isAuthenticated()) {
		// If user is already logged in, redirect to homepage
		res.redirect("/homepage");
	} else {
		// Otherwise show the public landing page
		res.render("index.ejs");
	}
});

app.get("/login", (req, res) => {
	res.render("login.ejs");
});

app.get("/signup", (req, res) => {
	res.render("signup.ejs");
});

app.get("/homepage", (req, res) => {
	if (req.isAuthenticated()) {
		res.render("partials/homepage", {user: req.user});
	} else {
		res.redirect("/login");
	}
});

// Update the login route to use passport
app.post(
	"/login",
	passport.authenticate("local", {
		successRedirect: "/homepage",
		failureRedirect: "/login",
	})
);

app.post("/signup", async (req, res) => {
	const {name, email, password} = req.body;

	// Check if user already exists
	try {
		const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);
		if (checkResult.rows.length > 0) {
			res.send("User already exists");
		} else {
			// Hash the password
			bcrypt.hash(password, saltRounds, async (err, hash) => {
				if (err) {
					res.send("Error hashing password");
				} else {
					// Insert the user into the database
					try {
						await db.query("INSERT INTO users (name, email, password) VALUES ($1, $2, $3)", [name, email, hash]);
						res.redirect("/login");
					} catch (error) {
						res.send("Error creating user");
					}
				}
			});
		}
	} catch (error) {
		console.log(error);
		res.send("Error checking user");
	}
});

app.get("/logout", (req, res) => {
	req.logout(function (err) {
		if (err) {
			console.log(err);
			return next(err);
		}
		res.redirect("/");
	});
});

// Set up the passport strategy
passport.use(
	new Strategy(
		{
			// Configure strategy to use email field instead of username
			usernameField: "email",
			passwordField: "password",
		},
		async function verify(email, password, cb) {
			try {
				const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
				console.log(`Login attempt for email: ${email}`);
				console.log(`User found: ${result.rows.length > 0}`);

				if (result.rows.length > 0) {
					const user = result.rows[0];
					const storedHashedPassword = user.password;

					bcrypt.compare(password, storedHashedPassword, (err, result) => {
						if (err) {
							console.log("Error comparing passwords:", err);
							return cb(err);
						} else {
							console.log(`Password match result: ${result}`);
							if (result) {
								// Passwords match
								return cb(null, user);
							} else {
								// Passwords do not match
								return cb(null, false, {message: "Incorrect password"});
							}
						}
					});
				} else {
					return cb(null, false, {message: "User not found"});
				}
			} catch (err) {
				console.log("Database error:", err);
				return cb(err);
			}
		}
	)
);

passport.serializeUser((user, cb) => {
	cb(null, user);
});

passport.deserializeUser((user, cb) => {
	cb(null, user);
});

app.listen(PORT, () => {
	console.log(`Server running on localhost:${PORT}`);
});
