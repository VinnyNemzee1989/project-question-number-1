// server.js

require("dotenv").config();
require("express-async-errors");
const express=require("express");
const mongoose=require("mongoose");
const morgan=require("morgan");
const cors=require("cors");

const authRoutes=require("./routes/auth");
const productRoutes=require("./routes/products");
const cartRoutes=require("./routes/cart");
const orderRoutes=require("./routes/orders");
const adminRoutes=require("./routes/admin");

const {errorHandler}=require("./middleware/errorHandler");

const app= express();
app.use(cors());
app.use(express.json());
app.use(morgan("dev"));

app.get("/",(req,res)=>res.json({ok: true, message: "E-commerce backend running"}));
app.use("/api/auth",authRoutes);
app.use("/api/products",productRoutes);
app.use("/api/cart",cartRoutes);
app.use("/api/orders",orderRoutes);
app.use("/api/admin",adminRoutes);

app.use(errorHandler);
const PORT=process.env.PORT||4000;

async function start(){
    if(!process.env.MONGO_URL) throw new Error("MONGO_URL missing in .env");
    await mongoose.connect(process.env.MONGO_URL);
    console.log("connected to MongoDB");
    app.listen(PORT,()=>console.log("server listening on ${PORT"));
}
start().catch(err=>{
    console.error(err);
    process.exit(1);
});

//models/User.js
const mongoose=require("mongoose");

const userSchema=new mongoose.Schema({
    name:{type:String, required:true},
    email:{type:String,required:true, unique:true},
    passwordHash:{type:String, required:true},
    role:{type:String, enum:["user","admin"],default:"user"},
    createdAt:{type:Date, default:Date.now}
});
module.exports=mongoose.model("user",userSchema);

//models/Product.js
const mongoose=require("mongoose");

const productSchema=new mongoose.Schema({
    tittle:{type:String, required:true},
    slug:{type:String, required:true, unique:true},
    description: String,
    price:{type:Number, required:true}, // store cents OR whole units consistently
    currency:{type:String, default:"USD"},
    images:[string],
    category:{type:string},
    stock:{type:Number, default:0},
    attributes:{type:Object},
    createdAt:{type:Date, default:Date.now},
    updatedAt:{type:Date, default:Date.now}
});
module.exports=mongoose.model("product",productSchema);

//models/Cart.js
const mongoose=require("mongoose");

const cartItemSchema= new mongoose.Schema({
    product:{type:mongoose.Schema.Types.ObjectId, ref: "product", required: true},
    quantity:{type: Number,required: true, default:1},
    priceAtAdd:{type:Number}
}, {_id: false});
const cartSchema= new mongoose.Schema({
    user:{type:mongoose.Schema.Types.ObjectId, ref:"user"}, //optional for guest carts
    items:[cartItemSchema],
    createdAt:{type:Date, default:Date.now},
    updatedAt:{type:Date,default:Date.now}
});
module.exports=mongoose.model("cart", cartSchema);

//models/order.js
const mongoose=require("mongoose");

const orderItemSchema= new mongoose.Schema({
    product:{type:mongoose.Schema.Types.ObjectId, ref: "product", required: true},
    name: string ,
    quantity: Number,
    price: Number,

}, {_id: false});

const orderSchema= new mongoose.Schema({
    user:{type: mongoose.Schema.Types.ObjectId,ref:"user"},
    items:[orderItemSchema],
    subtotal: Number,
    shipping: Number,
    tax: Number,
    total: Number,
    currency: {type: string, default: "USD"},
    status:{type:string, default:"pending"}, // pending, paid, processing, shipped, delivered, cancelled
    paymentIntentId:string,
    shippingAddress: Object,
    createdAt:{type:Date, default:Date.now},
    updatedAt:{type:Date, default:Date.now}
});
module.exports=mongoose.model("Order", orderSchema);

//middleware/auth.js
const jwt=require("jsonwebtoken");

exports.authenticate=(req,res,next)=>{
    const auth=req.headers.authorization;
    if(!auth) return res.status(401).json({error:"No token provided"});
    const token= auth.split("")[1];
    try{
        const payload= jwt.verify(token, process.env.JWT_SECRET);
        req.user= payload; // {id, role}
        next();

    } catch(err){
        return res.status(401).json({ error:"Invalid token"});
    }
}
exports.authorize=(role)=>(req, res, next)=>{
    if(!req.user) return res.status(401).json({error:"Not authenticated"});
    if(req.user.role !==role) return res.status(403).json({error:"Forbidden"});
    next();
}

//middleware/errorHandler.js
exports.errorHandler=(err, req, res, next)=>{
    console.error(err);
    const status=err.status||500;
    res.status(status).json(({error:err.message||"Server error"}));
}

//routes/auth.js
const express= require("express");
const bcrypt=require("bcryptjs");
const jwt=require("jsonwebtoken");
const User=require("../models/User");

function signAccess(user){
    return jwt.sign({id:user._id,role:user.role}, process.env.JWT_SECRET,{expiresIn: process.env.JWT_EXPIRES_IN ||"15"});

}
router.post("/register",async(req,res)=>{
    const {name, email, password}= req.body;
    if(!name||!email||!password) return res.status(400).json({error:"Missing fields"});
    const exits=await User.findOne({email});
    if(exists) return res.status(409).json({error:"Email already in use"});
    const salt=await bcrypt.genSalt(10);
    const passwordHash=await bcrypt.hash(password, salt);
    const user=await User.create({name,email,passwordHash});
    const accessToken=signAccess(user);
    res.status(201).json({accessToken,user:{id:user._id, email: user.email, name: user.name, role: user.role}});
});
router.post("/login",async(req,res)=>{
    const{email, password}= req.body;
    if(!email||password) return res.status(400).json({error:"Missing field"});
    const user= await User.findOne({email});
    if(!user)return res.status(401).json({error: "Invalid credentials"});
    const match= await bcrypt.compare(password, user.passwordHash);
    if(!match)return res.status(401).json({error:"invalid credentials"});
    const accessToken= signAccess(user);
    res.json({accessToken, user:{id:user._id, email:user.email, name:user.name, role:user.role}});
});
module.exports=router;

//routes/products.js
const express=require("express");
const product=require("../models/product");
const Router= express.Router();

// GET/api/products-query params:q, category, page, limit, sort
router.get("/", async(req, res)=>{
    const {q, category, page=1, limit=12}=req.query;
    const filter={};
    if(q) filter.tittle={$regex:q, $options:"i"};
    if(category) filter.category= category;
    const skip=(Number(page)-1)*Number(limit);
    const products=await product.find(filter).skip.limit(Number(limit));
    const total=await product.countDocuments(filter);
    res.json({data:products, total});
});
//GET/api/products/:slug
router.get("/:slug", async(req,res)=>{
    const p=await product.findOne({slug:req.params.slug});
    if(!p)return res.status(404).json({error:"Not found"});
    res.json(p);
});
module.exports=router;

// routes/cart.js
const express=require("express");
const cart=require("../models/cart");
const product= require("../models/product");
const {authenticate}=require("../middleware/auth");

// simple server-side cart for logged-in users
router.get("/",authenticate,async(req, res)=>{
    let cart=await cart.findOne({user:req.use.id}).populate("items.product");
    if(!cart) cart=await cart.create({user:req.user.id, items:[]});
    res.json(cart);
});
router.post("/", authenticate, async(req, res)=>{
    //body:{productId, quantity}
    const{productId, quantity= 1}= req.body;
    const product=await product.findById(productId);
    if(!product) return res.status(404).json({error:"product not found"});
    let cart=await cart.findOne({user:req.user.id});
    if(!cart) cart=await cart.create({user:req.user.id, items:[]});
    const idx=cart.items.findIndex(i=> i.product.toString()===productId);
    if(idx>-1){
        cart.items[idx].quantity+=Number(quantity);
    }else{
        cart.items.push({product:productId, quantity:Number(quantity), priceAtAdd: product.price});
    }
    cart.updatedAt= new Date();
    await cart.save();
    res.json(cart);
});
router.delete("/:productId",authenticate, async(req,res)=>{
    const{productId}= req.params;
    const cart= await cart.findOne({user:req.user.id});
    if(!cart) return res.status(404).json({ error: "cart not found"});
    cart.items= cart.items.filter(i=> i.product.toString()!==productId);
    cart.updatedAt=new Date();
    await cart.save();
    res.json(cart);
});
module.exports=router;

//routes/orders.js
const express=require("express");
const order=require("../models/order");
const cart=require("../models/cart");
const product= require("../models/product");
const{authenticate}=require("../middleware/auth");
const stripe= require("stripe")(process.env.STRIPE_SECRET_KEY||"");

//GET/api/orders- list user's orders
router.get("/",authenticate, async(req,res)=>{
    const orders= await order.find({user: req.user.id}).sort({creadedAt:-1});
    res.json(orders);
});
//POST/api/orders/checkout- create order and payment intent
router.post("/checkout",authenticate, async(req,res));
const cart= await cart.findOne({user:req.user.id}).populate("items.product");
if(!cart||cart.items.length===0) return res.status(400).json({error:"cart empty"});
// calculate totals
const subtotal= cart.items.reduce((s,it)=>s+(it.priceAtAdd||it.product.price)*it.quantity, 0);
const shipping= 0;
const tax= 0;
const total= subtotal+shipping+tax;
//clear cart
cart.items=[];
await cart.save();
res.json({order, clientSecret:paymentIntent?.client_secret});

//routes/admin.js
const express= require("express");
const product= require("../models/product");
const order= require("../models/order");
const{authenticate, authorize}= require("../middleware/auth");
const router= express.Router();

//Admin product CRUD
router.post("/product", authenticate,authorize("admin"), async(req, res)=>{
    const p= await product.create(req.body);
    res.status(201).json(p);
});
router.put("/products/:id", authenticate,authorize("admin"), async(req,res)=>{
    const p= await product.findByIdAndUpdate(req.params.id, req.body, {new: true});
    res.json(p);
});
router.delete("/products/:id", authenticate, authorize("admin"), async(req, res)=>{
    await product.findByIdAndDelete(req.params.id);
    res.json({ok: true});
});
// admin orders
router.get("/orders",authenticate, authorize("admin"), async(req,res)=>{
    const orders= await order.find().sort({createdAt:-1});
    res.json(orders);
});
router.put("/orders/:id/status", authenticate, authorize("admin"), async(req,res)=>{
    const{status}=req.body;// expected: "processing", "shipped", "delivered", "cancelled"
    const order= await order.findById(req.params.id);
    if(!order) return res.status(404).json({error:"not found"});
    order.status= status;
    order.updatedAt= new Date();
    await order.save();
    res.json(order);
});
module.exports=router;
// seed.js
require("dotenv").config();
const mongoose= require("mongoose");
const bcrypt= require("bcryptjs");
const user= require("../models/user");
const product= require("../models/product");

async function seed(){
    if(!process.env.MONGO_URL) throw new Error("MONGO_URL required in .env");
    await mongoose.connect(process.env.MONGO_URL);
    console.log("connected");
};
// create admin
const adminEmail= "nemurambav@gmail.com";
let admin= await user.findOne({email: adminEmail});
if(!admin){
    const passwordHash= await bcrypt.hash("password123", 10);
    admin= await user.create({name:"Admin", email: adminEmail, passwordHash, role: "admin"});
    console.log("admin created", adminEmail);
}
