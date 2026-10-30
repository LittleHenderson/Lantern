const express = require("express")
const app = express()

function login(req, res) {
  res.send(check(req.body))
}

function check(body) {
  return !!body
}

app.get("/health", (req, res) => {
  res.send(check({}))
})
app.post("/login", login)
app.listen(3000)
