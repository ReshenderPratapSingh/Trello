const jwt = require("jsonwebtoken");
const {Pool} = require("pg");
const pool = new Pool({
    connectionString: process.env.DATABASE_URL
});

function authMiddleware(req, res, next) {
    const token = req.headers.token;

    if(!token) {
        return res.status(401).json({
            message: "unauthorized access"
        });
    }

    const decode = jwt.verify(token, "pratap");
    const userId = decode.userId;

    if(!userId) {
        return res.status(401).json({
            message: "malformed token"
        });
    }
    req.userId = userId;
    next();
}
async function adminMiddleware(req, res, next) {
    const userId = req.userId;
    const orgId = req.params.orgId;
    
    try {
        const response = await pool.query(
        `SELECT * FROM members 
        WHERE user_id = $1 AND org_id = $2 AND role = 'admin'`,
        [userId, orgId]
        );

        if(!response.rows[0]) {
            return res.status(403).json({ message: "you are not an admin" });
        }
        next();
    } catch(error) {
        return res.status(403).json({message: "something went wrong"});
    }

}
module.exports = {authMiddleware, adminMiddleware};