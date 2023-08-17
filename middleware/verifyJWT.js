
const jwt = require('jsonwebtoken');


const verifyJWT = async (req, res, next)=> {
    const authHeader = req.headers['authorization'];
    if(!authHeader) return res.status(401);
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
        req.user = decoded.username
        next();
    } catch(err) {
        return res.status(404);
    };
};

module.exports = verifyJWT;
