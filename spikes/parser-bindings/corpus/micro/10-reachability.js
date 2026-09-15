import express from "express";
import { template } from "lodash";

const app = express();

function renderWelcome(name) {
  return template("hi <%= n %>")({ n: name });
}

function sendWelcome(res, name) {
  res.send(renderWelcome(name));
}

app.get("/welcome", (req, res) => sendWelcome(res, req.query.name));

export default app;
