require("dotenv").config();
const express = require("express");
const {Pool} = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const z = require("zod");
const { id } = require("zod/locales");
const {authMiddleware, adminMiddleware} = require("./middleware");
const app = express();
const pool = new Pool({
    connectionString: process.env.DATABASE_URL
});

const SignupSchema = z.object({
    username: z.string().min(3),
    email: z.email(),
    password: z.string().min(8)
});

const SigninSchema = z.object({
    username: z.string().min(3),
    password: z.string().min(8)
});

const createOrgSchema = z.object({
    name: z.string(),
    description: z.string().max(100)
})

const addMemberSchema = z.object({
    email: z.email()
});

const addIssueSchema = z.object({
    name: z.string()
});

const createBoardSchema = z.object({
    name: z.string().min(3),
    description: z.string().max(1000)
})

app.use(express.json());

app.post("/signup", async (req, res) => {
    const {data, success, error} = SignupSchema.safeParse(req.body);
    if(!success){
        return res.status(400).json({
            message: "invalid inputs",
            error: JSON.parse(error)
        });
    }

    const username = data.username;
    const email = data.email;
    const password = data.password;
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
    const {data, success, error} = SigninSchema.safeParse(req.body);
    if(!success) {
        return res.status(400).json({
            mesasge: "invalid input",
            error : JSON.parse(error)
        })
    }

    const username = data.username;
    const password = data.password;

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

app.post("/create-organisation", authMiddleware,  async(req, res) => {
    const {data, success, error} = createOrgSchema.safeParse(req.body);

    if(!success) {
        res.status(400).json({
            message: "invalid inputs",
            error: JSON.parse(error)
        });
    }

    const organisationName = data.name;
    const description = data.description;

    try {
        const response = await pool.query(
            `INSERT INTO organisations (name, description) VALUES ($1, $2) RETURNING id`,
            [organisationName, description]
        );
        
        const orgId = response.rows[0].id;
        const userId = req.userId;

        await pool.query(
            `INSERT INTO members (user_id, org_id, role) VALUES ($1, $2, 'admin')`,
            [userId, orgId]
        );

        res.status(201).json({
            mesasge: "orgnisation added!",
        })
    } catch(error) {
        if(error.code == "23505") {
            if(error.constraint == "organisations_name_key") {
                return res.status(409).json({message: "organisation name already exist"});
            }
        } else {
            return res.status(500).json({message: "something went wrong"});
        }
    }

})

app.post("/organisation/:orgId/add-member", authMiddleware, adminMiddleware, async(req, res) => {
    const{data, success, error} = addMemberSchema.safeParse(req.body);
    if(!success) {
        return res.status(400).json({
            message: "invalid inputs",
            error: JSON.parse(error)
        });
    }
    const email = data.email;
    try{
        const response = await pool.query(
            `SELECT * FROM users
            WHERE email = $1`,
            [email]
        );
        if(!response.rows[0]) {
            return res.status(404).json({
                message: "user not found"
            });
        }
        const memberId = response.rows[0].id;
        const orgId = req.params.orgId;

        const isMember = await pool.query(
            `SELECT * FROM members
            WHERE user_id = $1 AND org_id = $2`,
            [memberId, orgId]
        );

        if(isMember.rows[0]) {
            return res.status(409).json({message: "user is alreday a part of your organisation"});
        }
        
        await pool.query(
            `INSERT INTO members (user_id, org_id, role) VALUES ($1, $2, 'member')`,
            [memberId, orgId]
        );

        res.status(201).json({message: "member added"});
    } catch(error) {
        return res.status(500).json({message: "something went wrong"});
    }
    
});

app.post("/organisation/:orgId/create-board", authMiddleware, adminMiddleware, async(req, res) => {
    const{data, success, error} = createBoardSchema.safeParse(req.body);

    if(!success) {
        return res.status(400).json({
            message: "invalid input",
            error: JSON.parse(error)
        });
    }

    const name = req.body.name;
    const description = req.body.description;
    const orgId = req.params.orgId;

    try{
        await pool.query(
            `INSERT INTO boards (name, description, org_id) VALUES ($1, $2, $3)`,
            [name, description, orgId]
        );

        res.status(201).json({
            message:"board added"
        });
    } catch(error) {
        return res.status(500).json({message: "something went wrong"});
    }
});

app.post("/organisation/:orgId/Board/:boardId/create-issue", authMiddleware, adminMiddleware, async(req, res) => {
    const{data, success, error} = addIssueSchema.safeParse(req.body);
    if(!success) {
        return res.status(400).json({
            message: "invalid input",
            error: JSON.parse(error)
        });
    }
    const name = data.name;
    const orgId = req.params.orgId;
    const boardId = req.params.boardId;

    try{
        await pool.query(
            `INSERT INTO issues (name, board_id) VALUES($1, $2)`,
            [name, boardId]
        );
        res.status(201).json({
            message: "issue added"
        });
    } catch(error) {
        res.status(500).json({message: "something went wrong"});
    }
});

app.listen(3000);