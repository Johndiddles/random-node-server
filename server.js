const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const v4 = require("uuid");
const { default: mongoose } = require("mongoose");
const users = require("./models/userSchema");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

dotenv.config();
const app = express();

app.use(
  cors({
    origin: "*`",
    credentials: true,
  })
);
app.use(express.json({ limit: "200mb" }));
app.use(cookieParser());
bodyParser.json();

// const databaseUri = process.env.MONGODB_URI;

const connectToDB = async () => {
  mongoose
    .connect(process.env.MONGODB_URI)
    .then(() => console.log("connected to database"))
    .catch((error) => console.log({ error }));
};

connectToDB();

app.get("/", (req, res) => {
  res.status(200).json({
    message: "",
    data: "Server entry point",
  });
});

app.get("/api/v1/users", (req, res) => {
  users
    .find()
    .then((allUsers) => {
      res.status(200).json(allUsers);
    })
    .catch((error) =>
      res
        .status(500)
        .json({ status: "failed", message: "an unexpected error occured" })
    );

  //   res.status(500).json({ message: "unknown error occured" });
});

app.post("/api/v1/users/create", async (req, res) => {
  const { id, name, email, password } = req.body;
  console.time("timeStarted");

  const newUser = new users({
    id,
    name,
    email,
    password,
  });

  newUser
    .save()
    .then(() => {
      res.status(201).json({
        message: "success",
        data: {
          id,
          name,
          email,
        },
      });
    })
    .catch((error) => {
      res.status(500).json({
        error,
        message: "failed",
        data: "unknown error occured",
      });
    });

  console.timeEnd("timeStarted");
});

app.post("/api/v1/login", async (req, res) => {
  const { email, password } = req.body;

  users
    .findOne({ email })
    .then(async (user) => {
      if (user) {
        const { name, email, id } = user;
        if (user.password === password) {
          const accessToken = jwt.sign(
            { name, email, id },
            process.env.JWT_ACCESS_SECRET,
            { expiresIn: "10s" }
          );
          const refreshToken = jwt.sign(
            { name, email, id },
            process.env.JWT_REFRESH_SECRET,
            { expiresIn: "15s" }
          );

          res.cookie("refreshToken", refreshToken, {
            expires: Math.floor(new Date(Date.now()) + 90000),
            // maxAge: 60 * 5,
            httpOnly: true,
            secure: true,
            sameSite: "none",
          });

          res.status(200).json({
            message: "success",
            // token: accessToken,
            user: { email, name },
          });
        } else {
          res
            .status(401)
            .json({ message: "failed", data: "invalid login details" });
        }
      } else {
        res.status(400).json({ message: "failed", data: "user not found" });
      }
    })
    .catch((error) => {
      console.log({ error });
      res
        .status(500)
        .json({ message: "failed", data: "an unknown error occured" });
    });
});

app.get("/api/v1/verify", (req, res) => {
  const accessToken = req.headers?.authorization ?? "";
  const current_time = Math.floor(new Date(Date.now()));

  if (accessToken) {
    const decoded = jwt.decode(accessToken, process.env.JWT_ACCESS_SECRET);

    if (decoded.exp * 1000 < current_time) {
      return res.status(401).json({ message: "failed", data: "unauthorized" });
    }
    return res.status(200).json({ message: "verified", decoded });
  } else {
    res.status(403).json({ message: "naaah" });
  }
});

app.get("/api/v1/renew-access-token", (req, res) => {
  const refreshToken = req.cookies?.refreshToken ?? "";
  if (refreshToken) {
    // decode refreshToken
    const current_time = Math.floor(new Date(Date.now()));
    const { id, name, email, exp } = jwt.decode(
      refreshToken,
      process.env.JWT_REFRESH_SECRET
    );

    if (exp * 1000 < current_time) {
      return res.status(401).json({ message: "failed", data: "unauthorized" });
    } else {
      const accessToken = jwt.sign(
        { name, email, id },
        process.env.JWT_ACCESS_SECRET,
        { expiresIn: "10s" }
      );
      const refreshToken = jwt.sign(
        { name, email, id },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: "15s" }
      );

      res.cookie("refreshToken", refreshToken, {
        expires: new Date(Date.now() + 900000),
        httpOnly: true,
        secure: true,
        sameSite: "none",
      });
      res.status(200).json({ message: "verified", token: accessToken });
    }
  } else {
    res.status(403).json({ message: "naaah" });
  }
});

app.listen(5775, () => console.log("listening on port: 5775"));
