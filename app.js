const express = require('express')
const cors = require('cors')
const app = express()
const bodyParser = require('body-parser')
const jsonParser = bodyParser.json()
const bcrypt = require('bcrypt')
const saltRounds = 10
const jwt = require('jsonwebtoken')
const secret = 'CAME DOWN'

const mysql = require('mysql2')

app.use(cors())

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  database: 'mydb'
});

app.post('/register', jsonParser, function (req, res, next) {
  bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
    if (err) {
      return res.json({
        status: 'error',
        message: err
      })
    }

    connection.execute(
      'INSERT INTO users (email, password, fname, lname, role) VALUE (?, ?, ?, ?, ?)',
      [req.body.email, hash, req.body.fname, req.body.lname, req.body.role],
      function (err, results, fields) {
        if (err) {
          return res.json({
            status: 'error',
            message: err
          })
        }

        res.json({
          status: 'success',
          message: 'Account created successfully.'
        })
      }
    );
  });
})

app.post('/login', jsonParser, function (req, res, next) {
  connection.execute(
    'SELECT * FROM users WHERE email=?',
    [req.body.email],
    function (err, results, fields) {
      if (err) {
        return res.json({
          status: 'error',
          message: err
        })
      }

      if (results.length == 0) {
        return res.json({
          status: 'error',
          message: 'This account not found.'
        })
      }

      bcrypt.compare(req.body.password, results[0].password, function (err, isLogin) {

        if (isLogin) {
          const token = jwt.sign({
            email: results[0].email
          }, secret, { expiresIn: '1h' })
          return res.json({
            status: 'success',
            message: 'Login successfully.',
            token: token
          })
        } else {
          return res.json({
            status: 'error',
            message: 'Login failed.'
          })
        }
      });
    }
  );
})

app.post('/authen', jsonParser, function (req, res, next) {
  try {
    const token = req.headers.authorization.split(' ')[1]
    const decoded = jwt.verify(token, secret)
    return res.json({ 
      status: 'success',
      decoded 
    })
  } catch (err) {
    return res.json({
      status: 'error',
      message: err.message
    })
  }

})

app.listen(3333, function () {
  console.log('CORS-enabled web server listening on port 3333')
})