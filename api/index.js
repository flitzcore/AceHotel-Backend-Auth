const express = require("express");
const app = express();
const router = express.Router();
const mongoose = require("mongoose");
const helmet = require("helmet");
const xss = require("xss-clean");
const mongoSanitize = require("express-mongo-sanitize");
const compression = require("compression");
const cors = require("cors");
const passport = require("passport");
const httpStatus = require("http-status");
const validate = require("../src/middlewares/validate");
const config = require("../src/config/config");
const authValidation = require("../src/validations/authValidations");
const authController = require("../src/controllers/authController");

const { jwtStrategy } = require("../src/config/passport");
const rateLimit = require("express-rate-limit");
const ApiError = require("../src/utils/ApiError");

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  skipSuccessfulRequests: true,
});

let server;

// set security HTTP headers
app.use(helmet());

// parse json request body
app.use(express.json());

// parse urlencoded request body
app.use(express.urlencoded({ extended: true }));

// sanitize request data
app.use(xss());
app.use(mongoSanitize());

// gzip compression
app.use(compression());

// enable cors
app.use(cors());
app.options("*", cors());

// jwt authentication
app.use(passport.initialize());
passport.use("jwt", jwtStrategy);

router.post(
  "/register",
  validate(authValidation.register),
  authController.register
);
// router.post("/login", validate(authValidation.login), authController.login);
// router.post("/logout", validate(authValidation.logout), authController.logout);
// router.post(
//   "/refresh-tokens",
//   validate(authValidation.refreshTokens),
//   authController.refreshTokens
// );
// router.post(
//   "/forgot-password",
//   validate(authValidation.forgotPassword),
//   authController.forgotPassword
// );
// router.post(
//   "/reset-password",
//   validate(authValidation.resetPassword),
//   authController.resetPassword
// );
// router.post(
//   "/send-verification-email",
//   auth(),
//   authController.sendVerificationEmail
// );
// router.post(
//   "/verify-email",
//   validate(authValidation.verifyEmail),
//   authController.verifyEmail
// );
app.use("/v1", router);
app.use((req, res, next) => {
  next(new ApiError(httpStatus.NOT_FOUND, "Not found"));
});
mongoose.connect(config.mongoose.url, config.mongoose.options).then(() => {
  console.log("Connected to MongoDB");
  server = app.listen(config.port, () => {
    console.log(`Listening to port ${config.port}`);
  });
});
const exitHandler = () => {
  if (server) {
    server.close(() => {
      logger.info("Server closed");
      process.exit(1);
    });
  } else {
    process.exit(1);
  }
};
const unexpectedErrorHandler = (error) => {
  console.log(error);
  exitHandler();
};

process.on("uncaughtException", unexpectedErrorHandler);
process.on("unhandledRejection", unexpectedErrorHandler);

process.on("SIGTERM", () => {
  console.log("SIGTERM received");
  if (server) {
    server.close();
  }
});

// app.get('/', (req, res) => {
//   const path = `/item/${v4()}`;
//   res.setHeader('Content-Type', 'text/html');
//   res.setHeader('Cache-Control', 's-max-age=1, stale-while-revalidate');
//   res.end(`<p>Hello! Go to item: <a href="${path}">${path}</a></p>`);
// });

// app.get('/item/:slug', (req, res) => {
//   const { slug } = req.params;
//   res.end(`<p>Item: ${slug}</p><a href="/">Go back</a>`);
// });

module.exports = app;
