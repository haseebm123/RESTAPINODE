const express = require("express");
const user_route = express();


user_route.set('view engine', 'ejs');
user_route.set('views', '../views');
user_route.use(express.static('public'));
const userController = require('../controllers/userController');
user_route.get("/mail-verification", userController.verifyEmail);
user_route.get("/mail-forget", userController.resetPasswordLoad);

module.exports = user_route;