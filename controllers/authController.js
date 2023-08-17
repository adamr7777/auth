const usersDB = {
    users: require('../model/users.json'),
    setUsers: function (data) { this.users = data }
};

const jwt = require('jsonwebtoken');

const fsPromises = require('fs').promises;
const path = require('path');



const bcrypt = require('bcrypt');

const handleLogin = async (req, res) => {
    const { user, pwd } = req.body;
    if (!user || !pwd) return res.status(400).json({ 'message': 'Username and password are required.' });
    const foundUser = usersDB.users.find(person => person.username === user);
    if (!foundUser) return res.sendStatus(401); //Unauthorized 
    // evaluate password 
    const match = await bcrypt.compare(pwd, foundUser.password);
    if (match) {
        // create JWTs
        const ACCESS_TOKEN = jwt.sign({"username": foundUser.username}, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '30s'});
        const REFRESH_TOKEN = jwt.sign({"username": foundUser.username}, process.env.REFRESH_TOKEN_SECRET, {expiresIn: '1d'});
       
        const currentUser = {...foundUser, REFRESH_TOKEN};
        const otherUsers = usersDB.users.filter((item)=> item.username !== foundUser.username);
        usersDB.setUsers([...otherUsers, currentUser]);

        await fsPromises.writeFile(path.join(__dirname, '..', 'model', 'users.json'), JSON.stringify(usersDB.users));
    
        res.cookie('jwt', REFRESH_TOKEN, {httpOnly: true, sameSite: 'None', secure: true, maxAge: 24 * 60 * 60 * 1000})
        res.json({ACCESS_TOKEN});
    } else {
        res.sendStatus(401);
    }
}

module.exports = { handleLogin };