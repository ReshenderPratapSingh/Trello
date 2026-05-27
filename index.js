require("dotenv").config();
const express = require("express");
const {Pool} = require("pg");
const bcrypt = require("bcrypt");
const app = express();
const pool = new Pool({
    connectionString: process.env.DATABASE_URL
});

app.use(express.json());
app.post("/signup", async (req, res) => {
    const username = req.body.username;
    const email = req.body.email;
    const password = req.body.password;
    const hashedPassword = await bcrypt.hash(password, 10);
    try {
        const response = await pool.query(
            `INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id`,
            [username, email, hashedPassword]
        );
        
        res.status(201).json({
            message: "signup done!",
            id: response.rows[0].id
        });
    } catch(error) {
        if(error.code === "23505") {
            if(error.constraint === "users_email_key") {
                return res.status(409).json({message: "email already exists"});
            } else if (error.constraint === "users_username_key") {
                return res.status(409).json({message: "username already exists"});
            }
        } else {
            return res.status(500).json({message: "something went wrong"});
        }
    }
});
app.listen(3000);