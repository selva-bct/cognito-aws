const express = require('express')
const authRouter = express.Router()
import authService from './../../service'

authRouter
    .post('/', authService.authenticate)
    .post('/signup', authService.register)
    .post('/changePassword', authService.changePassword)
    .get('/validateToken', authService.validateToken)
    .post('/firstTimeChangePassword', authService.firstTimeChangePassword)
    // .post('/confirmUser', authService.adminConfirmSignup)

 module.exports = authRouter