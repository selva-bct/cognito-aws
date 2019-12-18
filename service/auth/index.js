global.fetch = require('node-fetch');
global.navigator = () => null;

const { cognito } = require('config')
const request = require('request')
const jwkToPem = require('jwk-to-pem')
const jwt = require('jsonwebtoken')

let jwks

request({
    url: `https://cognito-idp.${cognito.poolRegion}.amazonaws.com/${cognito.userPoolId}/.well-known/jwks.json`,
    json: true
}, function (error, response, body) {
    if (!error && response.statusCode === 200) {
        jwks = body
    }
})

async function validateToken(req, res, next) {
    const token = req.headers['authorization'];
    const pems = {}
    const keys = jwks['keys']
    for (let i = 0; i < keys.length; i++) {
        const key_id = keys[i].kid
        const modulus = keys[i].n
        const exponent = keys[i].e
        const key_type = keys[i].kty
        const jwk = { kty: key_type, n: modulus, e: exponent }
        const pem = jwkToPem(jwk)
        pems[key_id] = pem
    }
    var decodedJwt = jwt.decode(token, { complete: true })
    if (!decodedJwt) {
        console.log("Not a valid JWT token")
        res.status(401);
        return res.send("Invalid token")
    }
    var kid = decodedJwt.header.kid
    console.log("decodedJwt :: ", decodedJwt)
    var pem = pems[kid]
    if (!pem) {
        console.log('Invalid token')
        res.status(401)
        return res.send("Invalid token")
    }
    // need to check the expiry of the token
    const { payload: { exp } } = decodedJwt
    if (new Date(exp) < new Date()) {
        res.status(401)
        return res.send("Expired token")
    }
    jwt.verify(token, pem, function (err, payload) {
        if (err) {
            console.log("Invalid Token.");
            res.status(401);
            return res.send("Invalid tokern");
        } else {
            console.log("Valid Token.");
            res.json({
                message: 'Valid token'
            })
        }
    });
}


const AWS = require("aws-sdk");
AWS.config.update({
    accessKeyId: cognito.accessKeyId,
    secretAccessKey: cognito.secretAccessKey,
    region: cognito.poolRegion
})


const cognitoClient = new AWS.CognitoIdentityServiceProvider({
    apiVersion: "2016-04-19",
    region: cognito.poolRegion
})


async function register(req, res, next) {
    try {
        const { body: { name, email, password, phone } } = req
        var poolData = {
            UserPoolId: cognito.userPoolId,
            Username: name,
            DesiredDeliveryMediums: ["EMAIL"],
            TemporaryPassword: password,
            UserAttributes: [
                {
                    Name: "email",
                    Value: email
                },
                {
                    Name: 'phone_number',
                    Value: phone
                }
            ]
        }
        const userData = await adminCreateUser(poolData)
        res.json({
            statusCode: 200,
            body: userData
        })

    } catch (error) {
        console.log("error :: ", error)
        res.json({
            message: 'Error while creating user'
        })
    }
}

const adminCreateUser = (poolData) => {
    new Promise((resolve, reject) => {
        cognitoClient.adminCreateUser(poolData, (error, data) => {
            if (error) {
                return reject(error)
            }
            resolve(data)
        })
    })
}

const adminConfirmSignup = async (req, res) => {
    try {
        const { username } = req.body
        const options = {
            UserPoolId: cognito.userPoolId,
            Username: username
        }
        await new Promise((resolve, reject) => {
            cognitoClient.adminConfirmSignUp(options, function (err, data) {
                if (err)
                    return reject(err)
                resolve(data)
            })
        })
        return res.json({
            message: 'Successfully Confirmed User'
        })
    } catch (error) {
        res.json({
            statusCode: 401,
            message: 'Failed to Confirm users'
        })
    }
}

const changePassword = async (req, res) => {
    try {
        const { oldPassword, newPassword } = req.body
        const { authorization } = req.headers
        const data = await new Promise((resolve, reject) => {
            const options = {
                AccessToken: authorization,
                PreviousPassword: oldPassword,
                ProposedPassword: newPassword
            }
            cognitoClient.changePassword(options, function (err, result) {
                if (err) {
                    console.log('Error while changing password ', err)
                    return reject(err)
                }
                resolve(result)
            });
        })
        console.log('Successfully changed the password')
        return res.json({
            message: 'Successfully changed the password',
            data
        })
    } catch (error) {
        console.log('Error while changing password', err)
        return res.json({
            message: 'failed to change the password'
        })
    }
}

const authenticate = async (req, res) => {
    try {
        const { username, password } = req.body
        const payload = {
            UserPoolId: cognito.userPoolId,
            AuthFlow: "ADMIN_NO_SRP_AUTH",
            ClientId: cognito.appClientId,
            AuthParameters: {
                USERNAME: username,
                PASSWORD: password
            }
        }
        const response = await cognitoClient.adminInitiateAuth(payload).promise()
        res.json({
            data: response
        })
    } catch (error) {
        res.json({
            data: error
        })
    }
}

const firstTimeChangePassword = async (req, res) => {
    try {
        const { session, password, username } = req.body
        const response = await new Promise((resolve, reject) => {
            COGNITO_CLIENT.adminRespondToAuthChallenge({
                UserPoolId: cognito.userPoolId,
                ClientId: cognito.appClientId,
                ChallengeName: "NEW_PASSWORD_REQUIRED",
                ChallengeResponses: {
                    USERNAME: username,
                    NEW_PASSWORD: password
                },
                Session: session
            }, (err, data) => {
                if(err) {
                    console.log("Error while changing the password", err)
                    reject(err)
                }
                resolve(data)
            })
        })
        return res.json({
            message: "Successfully changed the password",
            accessToken: response.AuthenticationResult.AccessToken
        })
    } catch (error) {
        return res.json({
            message: "Error while changing the password",
            statusCode: 400
        })
    }
}

export {
    authenticate,
    changePassword,
    validateToken,
    register,
    adminConfirmSignup,
    firstTimeChangePassword
}