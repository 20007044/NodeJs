const express=require('express');
const cookie=require('cookie-parser');
const jwt=require('jsonwebtoken');
const bcrypt=require('bcrypt');
const { string } = require('i/lib/util');
const app=express();


app.set('view engine','ejs');
app.use(express.urlencoded());
app.use(cookie());
app.use(express.static(__dirname));

const mongoose=require('mongoose');

mongoose.connect('mongodb://127.0.0.1:27017',{dbName:'contactform'}).then(()=>console.log('connected')).catch((e)=>console.log(e));

const userSchema=mongoose.Schema({
  'name':String,
  'email':String,
  'password':String,
});

const userAuth=mongoose.model('userAuth',userSchema);

let isAuthenticated=(req,res,next)=>
{
    if(req.cookies.login!=null)
    {
       next();
    }
    else
    {
        res.render('login',{message:null});
    }
}

app.get('/',isAuthenticated,async (req,res)=>
{
   const jwtId=jwt.verify(req.cookies.login,"123456");
   let user=await userAuth.findById(jwtId.id);
   res.render('logout.ejs',{name:user.name});
});

app.get('/login',(req,res)=>{
    res.render('login');
});
// When user submit the data and press the button for login in login page and form is post and action is /login
app.post('/login',async (req,res)=>{
    const {email,password}=req.body;
    let user=await userAuth.findOne({email});
    if(user)
    {
        let isMatch=bcrypt.compare(password,user.password);
        if(isMatch)
        {
            const token=jwt.sign({id:user._id},"123456");
            res.cookie("login",token,{expires:new Date(Date.now()+60*1000),httpOnly:true});   
            res.redirect('/');
        }
        else
        {
            res.render('login',{message:'Incorrect Password!'});
        }
    }
    else
        res.redirect('/registeration');
});
app.get('/registeration',(req,res)=>{
    res.render('registeration');
});

app.post('/registeration', async (req,res)=>
{
    const {name,email,password}=req.body;

    let user=await userAuth.findOne({email:email});
    if(user)
    res.redirect('/login');
    else
    {
        const hashPassword=await bcrypt.hash(password,10);
        const id=await userAuth.create({name:name,email:email,password:hashPassword});
        const token=jwt.sign({id:id._id},"123456");
        res.cookie("login",token,{expires:new Date(Date.now()+60*1000),httpOnly:true});
        res.redirect('/');
    }
});
//When user clicks on logout button in logout page and form is get
app.get('/logout',(req,res)=>
{
   
    res.cookie("login",null,{expires:new Date(),httpOnly:true});
    res.redirect('/');
});


app.listen('8000',()=>console.log('work'));
