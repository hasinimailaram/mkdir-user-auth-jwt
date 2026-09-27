const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const sqlite3 = require("sqlite3").verbose();
const dotenv = require("dotenv");
const path = require("path");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
    console.error("JWT_SECRET is missing in .env file");
    process.exit(1);
}

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

// SQLite database
const db = new sqlite3.Database("./data/users.db", (err) => {
    if (err) {
        console.error("Database connection error:", err.message);
    } else {
        console.log("SQLite database connected.");
    }
});

// Create users table
db.run(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
`, (err) => {
    if (err) {
        console.error("Table creation error:", err.message);
    } else {
        console.log("Users table ready.");
    }
});


// =========================
// REGISTER
// =========================
app.post("/api/auth/register", async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({
            message: "Name, email and password are required."
        });
    }

    if (password.length < 6) {
        return res.status(400).json({
            message: "Password must be at least 6 characters."
        });
    }

    try {
        db.get(
            "SELECT id FROM users WHERE email = ?",
            [email],
            async (err, user) => {
                if (err) {
                    return res.status(500).json({
                        message: "Database error."
                    });
                }

                if (user) {
                    return res.status(409).json({
                        message: "Email already registered."
                    });
                }

                const hashedPassword = await bcrypt.hash(password, 10);

                db.run(
                    "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                    [name, email, hashedPassword],
                    function (err) {
                        if (err) {
                            return res.status(500).json({
                                message: "Registration failed."
                            });
                        }

                        res.status(201).json({
                            message: "Registration successful.",
                            userId: this.lastID
                        });
                    }
                );
            }
        );
    } catch (error) {
        console.error(error);
        res.status(500).json({
            message: "Server error."
        });
    }
});


// =========================
// LOGIN
// =========================
app.post("/api/auth/login", (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({
            message: "Email and password are required."
        });
    }

    db.get(
        "SELECT * FROM users WHERE email = ?",
        [email],
        async (err, user) => {
            if (err) {
                return res.status(500).json({
                    message: "Database error."
                });
            }

            if (!user) {
                return res.status(401).json({
                    message: "Invalid email or password."
                });
            }

            try {
                const passwordMatch = await bcrypt.compare(
                    password,
                    user.password
                );

                if (!passwordMatch) {
                    return res.status(401).json({
                        message: "Invalid email or password."
                    });
                }

                const token = jwt.sign(
                    {
                        id: user.id,
                        email: user.email
                    },
                    JWT_SECRET,
                    {
                        expiresIn: "1h"
                    }
                );

                res.cookie("token", token, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === "production",
                    sameSite: "lax",
                    maxAge: 60 * 60 * 1000
                });

                res.json({
                    message: "Login successful."
                });

            } catch (error) {
                console.error(error);
                res.status(500).json({
                    message: "Login failed."
                });
            }
        }
    );
});


// =========================
// JWT MIDDLEWARE
// =========================
function authenticateToken(req, res, next) {
    const token = req.cookies.token;

    if (!token) {
        return res.status(401).json({
            message: "Authentication required."
        });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        req.user = decoded;

        next();
    } catch (error) {
        return res.status(403).json({
            message: "Invalid or expired token."
        });
    }
}


// =========================
// PROTECTED ROUTE
// =========================
app.get("/api/protected", authenticateToken, (req, res) => {
    res.json({
        message: "You accessed a protected route.",
        user: req.user
    });
});


// =========================
// LOGOUT
// =========================
app.post("/api/auth/logout", (req, res) => {
    res.clearCookie("token");

    res.json({
        message: "Logged out successfully."
    });
});


// =========================
// START SERVER
// =========================
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Open http://localhost:${PORT}`);
});