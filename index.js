/**
 * 参考
 * https://reffect.co.jp/node-js/express-js%E3%81%A7json-web-tokenjwt%E3%81%AE%E8%A8%AD%E5%AE%9A%E3%82%92%E8%A1%8C%E3%81%86
 *
 */

const express = require("express");
const app = express();
const { expressjwt: jwt } = require("express-jwt");
const cors = require("cors");
const jsonwebtoken = require("jsonwebtoken");

const port = 5000;
const bcrypt = require("bcrypt");
const saltRounds = 10;

const jwtSecret = "secret";

const sqlite3 = require("sqlite3").verbose();

const db = new sqlite3.Database("./database/database.sqlite3", (err) => {
  if (err) {
    return console.error(err.message);
  }
  console.log("Connected to the SQlite database.");
});
app.use(express.json());
app.disable("etag");
var corsOptions = {
  credentials: true,
  origin: ["http://localhost:3000", "http://127.0.0.1:5000"],
};

app.use(cors(corsOptions));

app.get("/", (request, response) => response.send("Hello World!!"));

app.get("/httponly", async (req, res) => {
  const salt = await bcrypt.genSalt();
  const hashed = await bcrypt.hash(new Date().toLocaleString(), salt);

  // 参考: https://geekflare.com/enable-cors-httponly-cookie-secure-token/
  return res
    .cookie("token", hashed, {
      expires: new Date(Date.now() + 3600 * 1000 * 24 * 180 * 1), //second min hour days year
      secure: true, // set to true if your using https or samesite is none
      httpOnly: true, // backend only
      sameSite: "Strict", // set to none for cross-request
      //cookieをNoneにする場合はcookieにsecure属性が必須となる。
      //secure属性をつけるとhttps通信の時しかcookieのやりとりができなくなる。
      // ローカル環境でクロスオリジンクッキーを使う場合、Dockerなどを使ってhttps環境を作る必要がある
    })
    .json({
      message: "success",
    });
});

app.post("/httponly", async (req, res) => {
  const salt = await bcrypt.genSalt();
  const hashed = await bcrypt.hash(new Date().toLocaleString(), salt);

  // 参考: https://geekflare.com/enable-cors-httponly-cookie-secure-token/
  return res
    .cookie("token", hashed, {
      expires: new Date(Date.now() + 3600 * 1000 * 24 * 180 * 1), //second min hour days year
      // secure: true, // set to true if your using https or samesite is none
      httpOnly: true, // backend only
      sameSite: "strict", // set to none for cross-request
      //cookieをNoneにする場合はcookieにsecure属性が必須となる。
      //secure属性をつけるとhttps通信の時しかcookieのやりとりができなくなる。
      // ローカル環境でクロスオリジンクッキーを使う場合、Dockerなどを使ってhttps環境を作る必要がある
    })
    .json({
      message: "POST success",
    });
});

app.get("/api/users", (req, res) => {
  const sql = "select * from users";
  const params = [];
  db.all(sql, params, (err, rows) => {
    if (err) {
      return res.status(400).json({ error: err.message });
    }
    return res.json({
      message: "success",
      data: rows,
    });
  });
});

app.post("/api/auth/register/", (req, res) => {
  const insert = "INSERT INTO USERS (name, email, password) VALUES (?,?,?)";
  bcrypt.hash(req.body.password, saltRounds, (err, hash) => {
    db.run(insert, [req.body.name, req.body.email, hash], (err) => {
      if (err) {
        return res.status(400).json({ error: err.message });
      }
      return res.json({
        message: "create User successfully",
        data: [req.body.name, req.body.email],
      });
    });
  });
});

// ログイン + トークン取得
app.post("/api/auth/login/", (req, res) => {
  const sql = "select * from users where email = ?";
  const params = [req.body.email];
  db.get(sql, params, (err, user) => {
    if (err) {
      return res.status(400).json({ error: err.message });
    }
    if (!user) {
      return res.json({ message: "email not found" });
    }
    bcrypt.compare(req.body.password, user.password, (err, result) => {
      if (err) {
        return res.status(400).json({ error: err.message });
      }
      if (!result) {
        return res.json({ message: "password is not correct" });
      }

      // payloadにはTokenに含めたい情報を設定します。payloadはキーと値をペアに持つオブジェクト
      // トークンのデコード
      // https://jwt.io/#debugger
      const payload = {
        id: user.id,
        name: user.name,
        email: user.email,
      };

      const token = jsonwebtoken.sign(payload, jwtSecret);
      return res.json({ token });
    });
  });
});

// `/api/auth`以下のルートはすべてauthチェックされる
app.use(
  "/api/auth",
  jwt({
    secret: jwtSecret,
    algorithms: ["HS256"],
    // デフォルトではAuthorization: Bearerが、
    // 以下のものでcookieを取得してトークンを検討する
    // getToken: (req) => req.cookies.token,
  })
);

// 認証済みの場合はユーザー情報を取得できる。
app.get("/api/auth/user/", (req, res) => {
  const bearToken = req.headers["authorization"];
  const bearer = bearToken.split(" ");
  const token = bearer[1];

  return res.json({
    message: "Hello!",
  });
  //   jwt.verify(token, "secret", (err, user) => {
  //     if (err) {
  //       return res.sendStatus(403);
  //     } else {
  //       return res.json({
  //         user,
  //       });
  //     }
  //   });
});

app.listen(port, () => console.log(`Example app listening on port ${port}!`));
