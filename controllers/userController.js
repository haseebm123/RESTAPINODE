const { validationResult } = require("express-validator");
const bcrypt = require("bcryptjs");
const db = require("../config/dbConnection");
const Joi = require("joi");
const randomstring = require("randomstring");
const sendMail = require("../helpers/sendMail");
const register = (req, res) => {
  const schema = Joi.object({
    name: Joi.string().alphanum().min(3).max(10).required(),
    email: Joi.string().email().required(),
    password: Joi.string()
      .pattern(new RegExp("^[a-zA-Z0-9]{3,30}$"))
      .required(),
    repeat_password: Joi.string().required().valid(Joi.ref("password")),
  });
  const { error } = schema.validate(req.body);

  // const errors = validationResult(req);
  // if (!error.isEmpty()) {
  //   return res.status(400).json({
  //     errors: error.array(),
  //   });
  // }
  if (error) {
    return res.status(400).send({
      msg: error.details[0].message,
    });
  }
  db.query(
    `SELECT * FROM users WHERE LOWER(email) = LOWER(${db.escape(
      req.body.email
    )});`,
    (err, result) => {
      if (result && result.length) {
        return res.status(400).send({
          msg: "User Already Exist",
        });
      } else {
        bcrypt.hash(req.body.password, 10, (err, hash) => {
          if (err) {
            return res.status(400).send({
              msg: err,
            });
          } else {
            db.query(
              `INSERT INTO users (name,email,password) VALUES ('${
                req.body.name
              }',${db.escape(req.body.email)},${db.escape(hash)});`,
              (err, result) => {
                if (err) {
                  return res.status(400).send({
                    msg: err,
                  });
                }
                let mailSubject = "Mail Verification";
                const randomToken = randomstring.generate();
                let content = `<p> Hi ${req.body.name},Please 
                  <a href="http://127.0.0.1:3000/mail-verification?token${randomToken}">Verify</a> 
                  your mail
                </p>`;
                sendMail(req.body.email, mailSubject, content);
                db.query(
                  "UPDATE users set token=? where email=?",
                  [randomToken, req.body.email],
                  function (err, result, fileds) {
                    if (err) {
                      return res.status(400).send({
                        msg: err,
                      });
                    }
                  }
                );
                return res.status(200).send({
                  msg: "User Register Successfully",
                });
              }
            );
          }
        });
      }
    }
  );
};

module.exports = {
  register,
};
