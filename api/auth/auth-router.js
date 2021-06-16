const router = require("express").Router();
const bcrypt = require('bcryptjs')
const Users = require('../users/users-model')
const tokenBuilder = require('./token-builder')

const { checkUsernameExists, validateRoleName } = require('./auth-middleware');

router.post("/register", validateRoleName, (req, res, next) => {
  const { username, password } = req.body
  const { role_name } = req
  // bcrypting the password before saving
  const hash = bcrypt.hashSync(password, 8)

  // never save the plain text password in the db
  Users.add({ username, password: hash, role_name })
    .then(saved => {
      res.status(201).json(saved)
    })
    .catch(next); // our custom err handling middleware in server.js will trap this
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
})


router.post("/login", checkUsernameExists, (req, res, next) => {
  if (bcrypt.compareSync(req.body.password, req.user.password)) {
    const token = tokenBuilder(req.user)
    res.status(200).json({
      message: `${req.user.username} is back!`,
      token,
    });
  } else {
    next({
      status: 401,
      message: 'Invalid Credentials'
    })
  }
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
})

module.exports = router
