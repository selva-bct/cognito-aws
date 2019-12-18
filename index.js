// external package import
const express = require('express')
const bodyParser = require('body-parser')
const app = express()
const port = 3000

// internal pakage code 
import routes from "./router";

app.use(bodyParser.json()); // for parsing application/json
app.use(bodyParser.urlencoded({ extended: true })); // for parsing
app.use(routes)

app.listen(port, (err)=> {
    if(err) {
        console.log('Error starting server :: ', err)
        return
    }
    console.log('Server started in port :: ', port)
})