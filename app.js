//jshint esversion:6
require('dotenv').config(); // always to keep at the top of all code
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const validator = require("validator");
const catchAsync = require('./utils/catchAsync');
const bcrypt = require('bcrypt');

const signToken = id => {
    return jwt.sign({ id: newUser._id }, process.env.JWT_SECRET, {expiresIn: process.env.JWT_EXPIRES_IN});
}

const app = express();

console.log(process.env.API_KEY);

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));

mongoose.connect("mongodb://localhost:27017/userDB", {useUnifiedTopology:true});

// always specify fields for user in order to avoid automatic permition to register as an admin
const userSchema = new mongoose.Schema ({
    email: {
        type: String,
        required: [true, 'Please enter your e-mail'],
        lowercase: true,
        validate: [validator.isEmail, 'Please provide a valid email']
    },
    password :{
        type: String,
        required: [true, 'Please enter your password minimum 10 charachters and 1 upperCase'],
        minlength: 10,
        uppercase: 1
    }
  /*  passwordConfirmed: {
        type: String,
        required: [true, 'Please confirm your password'],
        validate: {
            //This only works on CREATE and SAVE!!!
            validator: function(el){
                return el === this.password;
            },
           message: 'Password is not the same' 
        } */
    
});




// before mongoose model which uses userSchema
//userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"]}); 

userSchema.pre('save', async function(next){
    // Only run this function if password was modified
    if(!this.isModified('password')) return next();

    // Hash the password with cost of 12
    this.password = await bcrypt.hash(this.password, 12);

    // Delete the passwordConfirmed field
  //  this.passwordConfirmed = undefined;
    next();
});



const User = new mongoose.model("User", userSchema);

module.exports = User;

app.get("/", function(req, res){
    res.render("home");
});

app.get("/login", function(req, res){
    res.render("login");
});

app.get("/register", function(req, res){
    res.render("register");
});

app.post("/register", catchAsync(async (req, res, next) => {
    // We allow only the data for a classical user, not admin
    const newUser = await new User({
        email: req.body.username,
        password: req.body.password,
      //  passwordConfirmed: req.body.password
    });

    const token = signToken(newUser._id);

    newUser.save(function(err){  // mongoose encrypt
        if(err){
            console.log(err);
        }else{
            console.log("No err, I am in res status");
            res.status(201).json({       
                status: 'success',
                token,
                data: {
                    user: newUser
                }
            });
            res.render("secrets");
            
        }
    });
    
}));

app.post("/login", catchAsync(async (req, res, next)=>{
    console.log("I am in login");
    const username = req.body.username;
    const password = req.body.password;

    const user = await User.findOne({email: username}, catchAsync(async (err, foundUser)=>{ // mongoose decrypt
        if(err){
            console.log(err);
        }else{
            console.log("I am in findUser");
            if(foundUser){
                console.log("User is found");
                 bcrypt.compare(password, foundUser.password, function(err, result){

                    if(result===true){
                        console.log("No errs, I am before token");
                        const token = signToken(user._id);
                        console.log("No errs, I am in res status" + user._id);
                        res.status(200).json({
                            status: 'success',
                            token
                        });
                        res.render("secrets");
                    }
                });    
            }
        }
    }));
}));    

app.listen(3000, function(){
    console.log("Server started on port 3000");
})