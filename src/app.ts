require("dotenv").config();
import express, { NextFunction, Request, Response, response } from "express";
import config from "config";
//import cors from "cors";
import morgan from "morgan";
import cookieParser from "cookie-parser";
import validateEnv from "./utils/validateEnv";
import { PrismaClient } from "@prisma/client";
import authRouter from "./routes/auth.routes";
import userRouter from "./routes/user.routes";
import AppError from "./utils/appError";

//import nodemailer from "nodemailer";

//require("dotenv").config();

/*
(async function () {
    //const credentials = await nodemailer.createTestAccount();

    const credentials = nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port: 587,
        secure: false,
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
        },
    });

    console.log(credentials);
})();
*/

validateEnv();

const prisma = new PrismaClient();
const app = express();

const cors = require("cors");
app.use(
    cors({
        origin: "*",
    })
);

//ssl
const fs = require("fs");
const http = require("http");
const https = require("https");

const privateKey = fs.readFileSync(
    "/etc/letsencrypt/live/bsmpl.musorilo.ru/privkey.pem",
    "utf8"
);
const certificate = fs.readFileSync(
    "/etc/letsencrypt/live/bsmpl.musorilo.ru/cert.pem",
    "utf8"
);
const ca = fs.readFileSync(
    "/etc/letsencrypt/live/bsmpl.musorilo.ru/chain.pem",
    "utf8"
);

const credentials = {
    key: privateKey,
    cert: certificate,
    ca: ca,
};

async function bootstrap() {
    // TEMPLATE ENGINE
    app.set("view engine", "pug");
    app.set("views", `${__dirname}/views`);

    // MIDDLEWARE

    // 1.Body Parser
    app.use(express.json({ limit: "10kb" }));

    // 2. Cookie Parser
    app.use(cookieParser());

    // 2. Cors
    app.use(
        cors({
            origin: [config.get<string>("origin")],
            credentials: true,
        })
    );

    // 3. Logger
    if (process.env.NODE_ENV === "development") app.use(morgan("dev"));

    // ROUTES
    app.use("/api/auth", authRouter);
    app.use("/api/users", userRouter);

    // Testing
    app.get("/api/healthchecker", (_, res: Response) => {
        res.status(200).json({
            status: "success",
            message: "Welcome to NodeJs with Prisma and PostgreSQL",
        });
    });

    // UNHANDLED ROUTES
    app.all("*", (req: Request, res: Response, next: NextFunction) => {
        next(new AppError(404, `Route ${req.originalUrl} not found`));
    });

    // GLOBAL ERROR HANDLER
    app.use(
        (err: AppError, req: Request, res: Response, next: NextFunction) => {
            err.status = err.status || "error";
            err.statusCode = err.statusCode || 500;

            res.status(err.statusCode).json({
                status: err.status,
                message: err.message,
            });
        }
    );

    const port = config.get<number>("port");
    /*
    app.listen(port, () => {
        console.log(`Server on port: ${port}`);
    });
    */

    const httpServer = http.createServer(app);
    const httpsServer = https.createServer(credentials, app);

    httpServer.listen(80, () => {
        console.log("HTTP Server running on port 80");
    });

    httpsServer.listen(443, () => {
        console.log("HTTPS Server running on port 443");
    });
}
