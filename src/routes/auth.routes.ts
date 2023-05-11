import express from "express";
import {
    forgotPasswordHandler,
    loginUserHandler,
    logoutUserHandler,
    refreshAccessTokenHandler,
    registerUserHandler,
    resetPasswordHandler,
    verifyEmailHandler,
} from "../controllers/auth.controller";
import { deserializeUser } from "../middleware/deserializeUser";
import { requireUser } from "../middleware/requireUser";
import { validate } from "../middleware/validate";
import {
    forgotPasswordSchema,
    loginUserSchema,
    registerUserSchema,
    resetPasswordSchema,
    verifyEmailSchema,
} from "../schemas/user.schema";
import { domainCheck } from "../utils/functions";

const router = express.Router();

router.post("/register", validate(registerUserSchema), registerUserHandler);

router.get("/register", validate(registerUserSchema), registerUserHandler);

router.get("/domaincheck", async (req, res, next) => {
    const email: string =
        req.query.email?.toString() !== undefined
            ? req.query.email?.toString()
            : "";
    const ans = await domainCheck(email);

    res.status(200).status(200).json({
        status: "success",
        email: email,
        answer: ans,
    });
});

/*
router.get("/test", async (req, res, next) => {
    const test = await getDomainByID(1345);
    res.status(200).json({
        message: test,
    });
});
*/

router.post("/login", validate(loginUserSchema), loginUserHandler);

router.get(
    "/verifyemail/:verificationCode",
    validate(verifyEmailSchema),
    verifyEmailHandler
);

router.get("/refresh", refreshAccessTokenHandler);

router.get("/logout", deserializeUser, requireUser, logoutUserHandler);

router.post(
    "/forgotpassword",
    validate(forgotPasswordSchema),
    forgotPasswordHandler
);

router.patch(
    "/resetpassword/:resetToken",
    validate(resetPasswordSchema),
    resetPasswordHandler
);

export default router;
