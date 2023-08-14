const nodemailer = require('nodemailer');
const { SMTP_MAIL, SMTP_PASSWORD } = process.env;

const sendMail = async (email, mailerSubject, content) => {
    try {
        var transport = nodemailer.createTransport({
          host: "sandbox.smtp.mailtrap.io",
          port: 2525,
          auth: {
            user: "a1ae1a951b2325",
            pass: "132fdad269c007",
          },
        });

        const mailOptions = {
          from: SMTP_MAIL,
          to: email,
          subject: mailerSubject,
          html: content,
        };

        transport.sendMail(mailOptions, function (error, info) {
            if (error) {
                
                console.log(error);
            } else {
                console.log("Mail sent successfully:-",info.response);
            }
        })
    } catch (error) {
        console.log(error.message);
    }
}

module.exports = sendMail;