const jwt = require("jsonwebtoken");
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
module.exports = {authMiddleware};