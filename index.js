const express = require("express");
const db = require("./db");
const app = express();
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require("bcryptjs");
var bodyParser = require('body-parser');
const nodemailer = require("nodemailer");
const crypto = require("crypto");
require('dotenv').config();

app.use(bodyParser.urlencoded({extended: false}));
app.set("view engine", "ejs");
app.use(bodyParser.json());
app.use(express.json());

app.get("/", (req, res) => {
    res.send("Welcome to my Node.js project");
});


app.get("/api/getUser", (req, res)=>{
    const userId = req.query.id;
    const sql = "SELECT * FROM users WHERE id = ? ";
    db.query(sql, [userId], (err, result)=>{
        if(err){
            return res.status(500).json({message: "Error fetching user"});
        }
        if(result.length === 0){
            return res.status(404).json({message: "user not found"});
        }
        res.json(result[0]);
    })
})

app.post("/api/signup", async (req, res) => {
    try {
        const { first_name, last_name, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(String(password), 10);
        const sql = "INSERT INTO users ( first_name,last_name, email, password ) VALUES (?,?,?,?)";
        db.query(sql, [first_name, last_name, email, hashedPassword], (err, result) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.json({ message: "user created successfully", userId: result.insertId });
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


app.post("/api/login", (req, res) => {
    const { email, password } = req.body;
    const sql = "SELECT * FROM users WHERE email = ?";
    db.query(sql, [email], async (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        console.log("user result", result);
        if (result.length === 0) {
            return res.status(401).json({ message: "user does not found" });
        }
        const users = result[0];
        try {
            const isMatch = await bcrypt.compare(String(password), users.password);
            if (!isMatch) {
                return res.status(401).json({ message: "invalid email or password" });
            }
            const token = jwt.sign({ id: users.id, email: users.email }, process.env.JWT_SECRET_KEY, { expiresIn: "1h" });
            res.json({ token });
        } catch (err) {
            console.error("error comparing", err);
            res.status(500).json({ message: "server" });
        }
    })
})

//setup nodemailer

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.Email_USER,
        pass: process.env.Email_PASS
    }
});
// app.get("/forget-password", (req, res)=>{
//     res.render("forget-password");
// });
app.post("/api/forget-password", (req, res) => {
    const { email } = req.body;
    db.query("SELECT * FROM users WHERE email = ?", [email], (err, result) => {
        if (err) return res.status(500).json({ message: "Database error" });
        if (result.length === 0) {
            return res.status(404).json({ message: "User not found" });
        }

        const token = crypto.randomBytes(32).toString("hex");
        const expiresAt = new Date(Date.now() + 3600000); // 1-hour expiry

        db.query(
            "UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE email = ?",
            [token, expiresAt, email],
            (err) => {
                if (err) return res.status(500).json({ message: "Error saving token" });

                const resetLink = `http://localhost:3000/api/reset-password?token=${token}`;
                
                const mailOptions = {
                    from: process.env.Email_USER,
                    to: email,
                    subject: "Password Reset Request",
                    html: `<p>You requested a password reset. Click the link below:</p>
                        <a href="${resetLink}">Reset Password</a>
                        <p>This link will expire in 1 hour.</p>`,
                };

                transporter.sendMail(mailOptions, (error) => {
                    if (error) {
                        console.error("Email sending error", error);
                        return res.status(500).json({ message: "Error sending email" });
                    }
                });

                res.json({ message: "Password reset email sent", resetLink });
            }
        );
    });
});



app.post("/api/reset-password", async (req, res) => {
    const { token, newPassword } = req.body;

    db.query(
        "SELECT * FROM users WHERE reset_token = ? AND reset_token_expiry > NOW()",
        [token],
        async (err, results) => {
            if (err) return res.status(500).json({ message: "Database error" });

            if (results.length === 0) {
                return res.status(400).json({ message: "Invalid or expired token" });
            }

            const userId = results[0].id;
            const hashedPassword = await bcrypt.hash(newPassword, 10);

            db.query(
                "UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?",
                [hashedPassword, userId],
                (updateErr) => {
                    if (updateErr) {
                        return res.status(500).json({ message: "Error updating password" });
                    }
                    res.json({ message: "Password reset successfully" });
                }
            );
        }
    );
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
