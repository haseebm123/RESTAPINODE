const { validationResult } = require("express-validator");
const bcrypt = require("bcryptjs");
const db = require("../config/dbConnection");
const Joi = require("joi");
const randomstring = require("randomstring");
const sendMail = require("../helpers/sendMail");
const jwt = require("jsonwebtoken");
const { JWT_SECRET } = process.env;
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
            var path;
            if (req.file && req.file.filename) {
              path = req.file.filename;
            } else {
              path = "default.png";
            }
            db.query(
              `INSERT INTO users (name,email,password,image) VALUES ('${
                req.body.name
              }',${db.escape(req.body.email)},
              ${db.escape(hash)},
              'image/${path}'
              );`,
              (err, result) => {
                if (err) {
                  return res.status(400).send({
                    msg: err,
                  });
                }
                let mailSubject = "Mail Verification";
                const randomToken = randomstring.generate();
                let content = `<p> Hi ${req.body.name},Please 
                  <a href="http://127.0.0.1:3000/mail-verification?token=${randomToken}">Verify</a> 
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

const verifyEmail = (req, res) => {
  var token = req.query.token;

  db.query(
    "SELECT * FROM users where token=? limit 1",
    token,
    function (error, result, fields) {
      if (error) {
        console.log(error.message);
      }
      if (result.length > 0) {
        db.query(`
        UPDATE users SET token = null, is_verified = 1 WHERE id = '${result[0].id}'
      `);
        return res.render("email_verification", {
          mesage: "Mail Verified Successfully",
        });
      } else {
        return res.render("404");
      }
    }
  );
  return res.status(200).send({
    msg: token,
  });
};

const login = (req, res) => {
  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string()
      .pattern(new RegExp("^[a-zA-Z0-9]{3,30}$"))
      .required(),
  });
  const { error } = schema.validate(req.body);

  if (error) {
    return res.status(400).send({
      msg: error.details[0].message,
    });
  }

  db.query(
    `SELECT * FROM users WHERE email= ${db.escape(req.body.email)} `,
    (error, result) => {
      if (error) {
        return res.status(400).send({
          msg: error,
        });
      }
      if (!result.length > 0) {
        return res.status(401).send({
          msg: "Invalid Email or Password",
        });
      }
      bcrypt.compare(req.body.password, result[0].password, (bErr, bResult) => {
        if (bErr) {
          return res.status(400).send({
            msg: bErr,
          });
        }

        if (bResult) {
          // console.log(JWT_SECRET);
          const token = jwt.sign(
            { id: result[0]["id"], is_admin: result[0]["is_admin"] },
            JWT_SECRET,
            { expiresIn: "1h" }
          );
          // return res.status(500).send({
          //   msg: token,
          // });
          db.query(
            `UPDATE users SET last_login = NOW() WHERE id = '${result[0]["id"]}'`
          );
          return res.status(200).send({
            msg: "Logged In",
            token,
            user: result[0],
          });
        }
      });
    }
  );
};

const getUser = (req, res) => {
  const authToken = req.headers.authorization.split(" ")[1];
  const decode = jwt.verify(authToken, JWT_SECRET);

  db.query(
    "SELECT * FROM users where id=?",
    decode.id,
    function (error, result, field) {
      if (error) throw error;
      return res.status(200).send({
        success: true,
        data: result[0],
        message: "Fetch Successfully",
      });
    }
  );
};
const forgetPassword = (req, res) => {
  const schema = Joi.object({
    email: Joi.string().email().required(),
  });
  const { error } = schema.validate(req.body);

  if (error) {
    return res.status(400).send({
      msg: error.details[0].message,
    });
  }

  var email = req.body.email;
  db.query(
    "SELECT * FROM users where email=? limit 1",
    email,
    function (error, result, fields) {
      if (error) {
        return res.status(400).send({
          message: error,
        });
      }
      if (result.length > 0) {
        let mailSubject = "Forget Password";
        const randomString = randomstring.generate();
        let content = `<p>Hi ${result[0].name} Please <a href="http://127.0.0.1:3000/mail-forget?token=${randomString}">Click Here</a> to reset your password</p>`;
        sendMail(email, mailSubject, content);
        db.query(
          `DELETE FROM password_resets WHERE email=${db.escape(result[0].email)}`
        );

        db.query(
          `INSERT INTO password_resets (email,token) VALUES(${db.escape(
            result[0].email
          )},'${randomString}')`
        );

        return res.status(200).send({
          message: "Mail Send Successfully for Forget Password",
          status: true,
        });
      }
      return res.status(401).send({
        message: "Email Does not Exist",
        status: false,
      });
    }
  );
   
};

const resetPasswordLoad = (req, res) => {
  try {
    var token = req.query.token;
    if (token == undefined) {
      res.render('404');
    }
    db.query(`SELECT 8 FROM password_resets WHERE token=? limit=1`, token, function (error, result, field) {
      if (error) {
        console.log(error);
      }
      if (!result.length > 0) {
        res.render("404");
      } else {
        db.query('SELECT * FROM users where email=? limit 1', result[0].email, function (error, result, fields) { 
            if (error) {
              console.log(error);  
          }
          res.render('reset-password', { user: result[0] });
        })  
        
      }
    } )
  } catch (error) {
    
  }
}

const resetPassword = (req, res) => {
  if (res.body.password != res.body.confirm_password) {
    res.render("reset-password", {
      error: "Password not match",
      user: { id: res.body.user_id, email: res.body.email },
    });
  }
  bcrypt.hash(req.body.confirm_password, 10, (error, hash) => {
    if (error) {
      console.log(error);
    }
    db.query(`DELETE FROM password_resets WHERE email= '${req.body.email}'`);
    db.query(
      `UPDATE users SET password='${hash}' WHERE id= '${req.body.user_id}'`
    );
    res.render("message", {
      message: "Password Update Successfully",
    });
  });
};

const updateProfile = (req, res) => {
  try {
    
    const schema = Joi.object({
      name: Joi.string().required(),
      // email: Joi.string().email().required(),
      // password: Joi.string()
      //   .pattern(new RegExp("^[a-zA-Z0-9]{3,30}$"))
      //   .required(),
      // repeat_password: Joi.string().required().valid(Joi.ref("password")),
    });
    const { error } = schema.validate(req.body);
  
    if (error) {
      return res.status(400).send({
        msg: error.details[0].message,
      });
    }
    const token = req.headers.authorization.split(' ')[1];
    const decode = jwt.verify(token, JWT_SECRET);
    var sql = '', data;
    if (req.file !== undefined ) {
      sql = `UPDATE users SET name =?, image=? WHERE user_id=?`;
      data = [req.body.name, 'image/' + req.file.filename,decode.id];
    } else {
      sql = `UPDATE users SET name =? WHERE id=?`;
      data = [req.body.name,decode.id];
    }

    db.query(sql, data, (error,result,field) => {
      if (error) {
         return res.status(400).send({
           msg: error,
         });
      }
      return res.status(200).send({
        msg: 'profile update successfully',
      });
    })
     
  } catch (err) {
    return res.status(400).send({
      msg: err,
    });
  }
};
module.exports = {
  register,
  verifyEmail,
  login,
  forgetPassword,
  getUser,
  resetPasswordLoad,
  resetPassword,
  updateProfile,
};
