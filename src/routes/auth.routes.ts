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

const router = express.Router();

router.post("/register", validate(registerUserSchema), registerUserHandler);

router.get("/register", validate(registerUserSchema), registerUserHandler);

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
