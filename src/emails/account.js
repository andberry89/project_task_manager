const sgMail = require("@sendgrid/mail");

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const sendWelcomeEmail = (email, name) => {
  sgMail.send({
    to: email,
    from: "andberry89@gmail.com",
    subject: "Thanks for signing up!",
    text: `Welcome to the app, ${name}. Let me know how you get along with the app.`,
  });
};

const sendCancelationEmail = (email, name) => {
  sgMail.send({
    to: email,
    from: "andberry89@gmail.com",
    subject: "Sorry to see you go!",
    text: `We're bummed that you're cancelling your account, ${name}. If you have a second, could you give us some feedback on why you've made this choice?`,
  });
};

module.exports = {
  sendWelcomeEmail,
  sendCancelationEmail,
};
