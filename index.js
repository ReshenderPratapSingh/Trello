require("dotenv").config();
const express = require("express");
const {Pool} = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
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
app.post("/signin", async(req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    const response = await pool.query(`SELECT * FROM users WHERE username = $1`, [username]);
    const userExists = response.rows[0];
    if(!userExists) {
        return res.status(404).json({
            message: "user not found"
        })
    } else {
        const isPasswordCorrect = await bcrypt.compare(password, userExists.password);
        if(isPasswordCorrect) {

            const token = jwt.sign({
                userId: userExists.id
            }, "pratap");

            res.status(201).json({
                message: "signin successful!",
                token: token
            });
        } else {
            res.status(400).json({
                message: "incorrect password!"
            });
        }
    }
})
app.listen(3000);