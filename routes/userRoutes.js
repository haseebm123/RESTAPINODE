const express = require('express');
const router = express.Router();
const { signUpValidation } = require('../helpers/validation');
const userController = require('../controllers/userController');
router.post("/register",userController.register);
// router.get("/register1", (req, res) => {
     
   
// });

module.exports = router;