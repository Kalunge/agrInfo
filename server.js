const express = require("express");
const colors = require("colors");
const dotenv = require("dotenv");
const morgan = require("morgan");
const errorHandler = require("./middleware/error");
const cookieParser = require("cookie-parser");
const connectDB = require("./config/db");

dotenv.config({ path: "./config/config.env" });

// require routes
const auth = require("./routes/auth");

connectDB();

const app = express();

app.use(express.json());

app.use(cookieParser());

// Dev logging middleware
if (process.env.NODE_ENV === "development") {
	app.use(morgan("dev"));
}

// mount routes
app.use("/api/v1/auth", auth);

app.use(errorHandler);

const PORT = process.env.PORT || 5000;
app.listen(
	PORT,
	console.log(
		`Serever listening on port ${PORT} on ${process.env.NODE_ENV}`.yellow.bold
	)
);
