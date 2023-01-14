const jwt = require(("jsonwebtoken"));
const secret = "dillion-secret"

const token = jwt.sign({email:'dillion@gmail.com'},secret)
// const token =     "bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2M2JkNDk3YzAwODJjOTA4OTBkYmQ1ZGYiLCJhZG1pbiI6dHJ1ZSwiaWF0IjoxNjczNTY0ODU5LCJleHAiOjE2NzM1Njg0NTl9.1pVItbs0Nyc-S9dhi5oKK_iD4suX_au3zjY58UMhGFY"
const realtoken = token//.split(" ")[1]
const decoded = jwt.decode(realtoken)
const verify = jwt.verify (realtoken, "dillion-secret")
console.log(
    {decoded,verify}
);