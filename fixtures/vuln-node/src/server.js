// Deliberately vulnerable Express handlers. Not a real application.
const express = require("express");
const { exec } = require("child_process");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const axios = require("axios");

const app = express();

app.get("/lookup", (req, res) => {
  // VULN: js.exec-tainted - command injection
  const domain = req.query.domain;
  exec("dig +short " + domain, (err, out) => res.send(out));
});

app.get("/file", (req, res) => {
  // VULN: js.path-tainted - path traversal
  const name = req.params.name || req.query.name;
  fs.readFile("/var/data/" + name, "utf8", (err, data) => res.send(data));
});

app.get("/proxy", (req, res) => {
  // VULN: js.ssrf-tainted
  const target = req.query.url;
  axios.get(target).then((response) => res.send(response.data));
});

app.get("/back", (req, res) => {
  // VULN: js.redirect-tainted - open redirect
  const next = req.query.next;
  res.redirect(next);
});

app.post("/login", (req, res) => {
  // VULN: js.jwt-hardcoded-secret
  const token = jwt.sign({ sub: req.body.user }, "keyboard-cat-secret-value");
  // VULN: config.cookie-insecure-flags
  res.cookie("session", token, { httpOnly: false });
  res.json({ token });
});

app.get("/search", (req, res) => {
  // VULN: js.sql-tainted
  const term = req.query.q;
  db.query(`SELECT * FROM items WHERE name LIKE '%${term}%'`, (err, rows) => res.json(rows));
});

app.get("/hello", (req, res) => {
  // VULN: js.xss-tainted - request data reflected into an HTML response
  const name = req.query.name;
  res.send(`<h1>Hello, ${name}</h1>`);
});

// VULN: js.express-trust-proxy-all
app.set("trust proxy", true);

module.exports = app;
