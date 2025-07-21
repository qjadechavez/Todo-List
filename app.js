/** @format */

import express from "express";
import bodyParser from "body-parser";
import pkg from "pg";
import session from "express-session";
import passport from "passport";
import {Strategy} from "passport-local";
import {Strategy as GoogleStrategy} from "passport-google-oauth20";
import {Strategy as FacebookStrategy} from "passport-facebook";
import bcrypt from "bcrypt";
import dotenv from "dotenv";

// Load environment variables
dotenv.config();

// Validate required environment variables
const requiredEnvVars = [
    'DB_USER', 'DB_HOST', 'DB_NAME', 'DB_PASSWORD', 'DB_PORT',
    'SESSION_SECRET', 'GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET',
    'FACEBOOK_APP_ID', 'FACEBOOK_APP_SECRET'
];

requiredEnvVars.forEach(envVar => {
    if (!process.env[envVar]) {
        console.error(`Missing required environment variable: ${envVar}`);
        process.exit(1);
    }
});

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

// Database connection pool
const { Pool } = pkg;
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
	
});

// Connection testing 
const testConnection = async () => {
    try {
        const client = await pool.connect();
        console.log('✓ Database connected successfully');
        client.release();
    } catch (err) {
        console.error('✗ Database connection failed:', err.message);
        process.exit(1);
    }
};

testConnection();

pool.on('error', (err) => {
    console.error('Unexpected database error:', err);
});

// Update the root route to check authentication
app.get("/", (req, res) => {
	if (req.isAuthenticated()) {
		res.redirect("/homepage");
	} else {
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

app.get("/auth/google", passport.authenticate("google", {
	scope: ["profile", "email"],
}));

app.get("/auth/google/homepage", passport.authenticate("google", {
	successRedirect: "/homepage",
	failureRedirect: "/login",
	})
);

app.get("/auth/facebook", passport.authenticate("facebook"));

app.get("/auth/facebook/homepage", passport.authenticate("facebook", {
	successRedirect: "/homepage",
	failureRedirect: "/login",
}));

// Update the login route to use passport
app.post(
	"/login",
	passport.authenticate("local", {
		successRedirect: "/homepage",
		failureRedirect: "/login",
	})
);

app.post("/signup", async (req, res) => {
    const { name, email, password } = req.body;

    // Basic validation
    if (!name || !email || !password) {
        return res.render("signup", { error: "All fields are required" });
    }

    if (password.length < 6) {
        return res.render("signup", { error: "Password must be at least 6 characters" });
    }

    try {
        const checkResult = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
        if (checkResult.rows.length > 0) {
            return res.render("signup", { error: "User already exists with this email" });
        }

        const hash = await bcrypt.hash(password, saltRounds);
        await pool.query("INSERT INTO users (name, email, password) VALUES ($1, $2, $3)", [name, email, hash]);
        res.render("login", { success: "Account created successfully! Please log in." });
    } catch (error) {
        console.error("Signup error:", error);
        res.render("signup", { error: "Something went wrong. Please try again." });
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
				const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);

				if (result.rows.length > 0) {
					const user = result.rows[0];
					const storedHashedPassword = user.password;

					console.log("Success User Login: ", user.name, "using local authentication");

					bcrypt.compare(password, storedHashedPassword, (err, isMatch) => {
						if (err) {
							console.log("Error comparing passwords:", err);
							return cb(err);
						} else {
							// Check if passwords match
							if (isMatch) {
								// Passwords match
								return cb(null, user);
							} else {
								// Passwords do not match
								return cb(null, false);
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

passport.use("google", new GoogleStrategy({
	clientID: process.env.GOOGLE_CLIENT_ID,
	clientSecret: process.env.GOOGLE_CLIENT_SECRET,
	callbackURL: "http://localhost:3000/auth/google/homepage",
	userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
}, async (accessToken, refreshToken, profile, cb) => {
	console.log("Email:", profile.emails[0].value);

	try {
		// Direct access to profile properties
		const email = profile.emails[0].value;
		const name = profile.displayName;

		console.log("Success User Login: ", name, "using google oauth");

		const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);

		if (result.rows.length === 0) {
			const newUser = await pool.query(
				"INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *", 
				[name, email, "google-oauth"]
			);
			return cb(null, newUser.rows[0]);
		} else {
			return cb(null, result.rows[0]);
		}

	} catch (error) {
		console.log("Google OAuth error:", error);
		return cb(error);
	}

}))

passport.use("facebook", new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/homepage",
    profileFields: ['id', 'displayName', 'email']
}, async (accessToken, refreshToken, profile, cb) => {
	
    // console.log("Facebook Profile:", profile);

    try {
        // Check if profile has email, otherwise use Facebook ID as email
        const email = profile.emails && profile.emails[0] 
            ? profile.emails[0].value 
            : `fb_${profile.id}@facebook.user`;
        const name = profile.displayName;

        console.log("Success User Login: ", name, "using facebook oauth");

        const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);

        if (result.rows.length === 0) {
            const newUser = await pool.query(
                "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *", 
                [name, email, "facebook-oauth"]
            );
            return cb(null, newUser.rows[0]);
        } else {
            return cb(null, result.rows[0]);
        }

    } catch (error) {
        console.log("Facebook OAuth error:", error);
        return cb(error);
    }
}));

passport.serializeUser((user, cb) => {
	cb(null, user.id);
});

passport.deserializeUser(async (id, cb) => {
	try {
		const result = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
		if (result.rows.length > 0) {
			cb(null, result.rows[0]);
		} else {
			cb(new Error("User not found"));
		}
	} catch (error) {
		cb(error);
	}
});

app.listen(PORT, () => {
	console.log(`Server running on http://localhost:${PORT}`);
});
