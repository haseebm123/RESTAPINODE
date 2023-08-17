require("dotenv").config();

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

var db = require('./config/dbConnection')

const userRouter = require("./routes/userRoutes");
const webRouter = require("./routes/webRouter");
const app = express();

app.use(express.json());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended:true}));
app.use(cors());

app.use('/api', userRouter);
app.use("/", webRouter);
app.use((err, req, res, next) => {
    err.statusCode = err.statusCode || 500;
    err.message = err.message || "Internal Server Error";
    res.status(err.statusCode).json({
        message: err.message,
    })
});

app.listen(3000, () => console.log("Server is running on port 3000"));