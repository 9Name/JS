const mongoose = require('mongoose');
const { isEmail } = require('validator');
var passwordHash = require('password-hash');
// const bcrypt = require('crypto');
const { Validator } = require('node-input-validator');
 
//

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: [true, 'Please enter an email'],
    unique: true,
    lowercase: true,
    validate: [isEmail, 'Please enter a valid email']
  },
  password: {
    type: String,
    required: [true, 'Please enter a password'],
    minlength: [6, 'Minimum password length is 6 characters'],
  }
});


// fire a function before doc saved to db      

userSchema.pre('save', async function(next) {
  var pas = this.password
  var hashedPassword = await passwordHash.generate(pas);
   this.password = hashedPassword
  
  next();
});


// static method to login user
userSchema.statics.login = async function(email, password) {
  const user = await this.findOne({ email });
  if (user) {
    // var hashedPassword = await passwordHash.generate('password123');
    // this.password = hashedPassword
      
    
   // const auth = await bcrypt.compare(password, user.password);
    if (passwordHash.verify(password, user.password)){
      console.log(user.password)
      return user;
    }
    throw Error('incorrect password');
  }
  throw Error('incorrect email');
};

const User = mongoose.model('user', userSchema);

module.exports = User;

