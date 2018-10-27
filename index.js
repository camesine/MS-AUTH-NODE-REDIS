const express = require("express");
const http = require("http");
const bodyParser = require("body-parser")
const jwt = require("jsonwebtoken");
const redis = require("redis").createClient(6379, "redis");
const app = express();
const server = http.createServer(app);
const CONFIG = require("./config");

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json({ limit: "50mb" }));

const jwtMiddleware = require("express-jwt")({ secret: CONFIG.SECRET });

app.post("/", (req, res, next) => {
  if (!req.body.userId) {
    res.status(400).json({ message: "userId is required" });
  }
  next();
}, (req, res) => {
  const { userId } = req.body;
  const token = jwt.sign(req.body, CONFIG.SECRET);
  redis.set(userId, token, "EX", CONFIG.TTL, (err, _) => {
    if (err) {
      const { message } = err;
      res.status(500).json({ message }).send();
    } else {
      res.status(200).json({ token }).send();
    }
  });
});

app.put("/", jwtMiddleware, (req, res) => {
  const { userId } = req.user;
  redis.get(userId, (err, token) => {
    if (err) {
      res.status(500).send();
    } else if (token !== req.headers.authorization.split(" ")[1]) {
      res.status(404).send();
    } else {
      redis.set(userId, token, "EX", CONFIG.TTL, (err, _) => {
        if (err) {
          const { message } = err;
          res.status(500).json({ message }).send();
        } else {
          res.status(200).json({ token }).send();
        }
      });
    }
  });
})

app.delete("/", jwtMiddleware, (req, res) => {
  const { userId } = req.user;
  redis.get(userId, (err, token) => {
    if (err) {
      res.status(500).send();
    } else if (token !== req.headers.authorization.split(" ")[1]) {
      res.status(404).send();
    } else {
      redis.del(userId, () => res.status(200).send());
    }
  });
})

app.use((req, res, next) => {
  res.status(404);
  res.json({
    error: "Not found",
  });
  next();
});

app.use((err, req, res, next) => {
  if (err.name === "UnauthorizedError") {
    res.status(401).json({
      error: "Please send a valid Token...",
    });
  }
  next();
});

server.listen(CONFIG.PORT, () => {
  console.log(`MS-AUTH LISTEN PORT ${CONFIG.PORT}`);
});
