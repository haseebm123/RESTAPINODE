const { check } = require('express-validator');

exports.SignUpValidation = [
  check("name", "Name Field is required").not().isEmpty(),
  check("email", "Please enter a valid mail").isEmail().normalizeEmail({gmail_remove_dots:true}),
  check("password", "Password is required").isLength({min:5}),
];

exports.SignInValidation = [
   check("email", "Please enter a valid mail")
    .isEmail() ,
  check("password", "Password is required").isLength({ min: 5 }),
];

