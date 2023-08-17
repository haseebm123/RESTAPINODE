const express = require('express');
const router = express.Router();
const { signUpValidation, SignInValidation } = require("../helpers/validation");
const userController = require('../controllers/userController');
const path = require('path')
const multer = require('multer');
const { isAuthorize } = require("../middleware/auth");
/* Upload Image */
    const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, path.join(__dirname, "../public/images"));
    },
    filename: function (req, file, cb) {
        const imgName = Date.now() + "-" + file.originalname;
        cb(null, imgName);
    },
    }); 
    const upload = multer({ storage: storage }) 
/* Upload Image */
 
/* API Routes */
router.post("/register",upload.single('image'),userController.register);
router.post("/login", userController.login);
router.post("/forget-password", userController.forgetPassword);
router.get("/get-user", isAuthorize, userController.getUser); 
router.get("/mail-forget", userController.resetPasswordLoad);
router.get(
  "/update-profile",
  upload.single("image"),
  isAuthorize,
  userController.updateProfile
);
/* End API Route */
module.exports = router;