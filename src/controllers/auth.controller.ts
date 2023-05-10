import crypto from "crypto";
import { CookieOptions, NextFunction, Request, Response } from "express";
import bcrypt from "bcryptjs";
import {
    ForgotPasswordInput,
    LoginUserInput,
    RegisterUserInput,
    ResetPasswordInput,
    VerifyEmailInput,
} from "../schemas/user.schema";
import {
    createUser,
    findUniqueUser,
    findUser,
    signTokens,
    updateUser,
} from "../services/user.service";
import { AcademicEnumType, Prisma } from "@prisma/client";
import config from "config";
import AppError from "../utils/appError";
import redisClient from "../utils/connectRedis";
import { signJwt, verifyJwt } from "../utils/jwt";
import Email from "../utils/email";
import {
    domainCheck,
    generateRandomPassword,
    getDomainByID,
} from "../utils/functions";
import { manual } from "prismjs";

const cookiesOptions: CookieOptions = {
    httpOnly: true,
    sameSite: "lax",
};

if (process.env.NODE_ENV === "production") cookiesOptions.secure = true;

const accessTokenCookieOptions: CookieOptions = {
    ...cookiesOptions,
    expires: new Date(
        Date.now() + config.get<number>("accessTokenExpiresIn") * 60 * 1000
    ),
    maxAge: config.get<number>("accessTokenExpiresIn") * 60 * 1000,
};

const refreshTokenCookieOptions: CookieOptions = {
    ...cookiesOptions,
    expires: new Date(
        Date.now() + config.get<number>("refreshTokenExpiresIn") * 60 * 1000
    ),
    maxAge: config.get<number>("refreshTokenExpiresIn") * 60 * 1000,
};

export const registerUserHandler = async (
    req: Request<{}, {}, RegisterUserInput>,
    res: Response,
    next: NextFunction
) => {
    try {
        //генерируем случайный пароль
        const hashedPassword = await bcrypt.hash(
            generateRandomPassword(10),
            12
        );

        //код верификации почты
        const verifyCode = crypto.randomBytes(32).toString("hex");
        const verificationCode = crypto
            .createHash("sha256")
            .update(verifyCode)
            .digest("hex");

        //проверить существует ли пользователь с такой почтой
        const userCheck = await findUser({
            email: req.body.email.toLowerCase(),
        });

        if (userCheck) {
            //если нашли
            /*
            //если существует, то
                //active = true ? 
                //если да, то редирект на sign in page с заполненным адресом
                //если нет, то проверяем verified = true, 
                    //если нет, то редирект на страницу check your email + повторно отсылаем почту с верификацией
                    //если да, то проверяем academic = true
                        //если да, то редирект на создание пароля
                        //если нет, то проверяем academic_type = manual 
                            //если да, то редирект we still working
                            //если нет, то отправляем лог админу и редиректим на страницу we still working
            */

            if (userCheck.active) {
                res.status(201).json({
                    status: "success",
                    code: "login",
                    email: userCheck.email,
                    message: "Email already exist and active.",
                });
            } else {
                if (userCheck.verified) {
                    if (userCheck.academic) {
                        //отправить на создание пароля
                        res.status(201).json({
                            status: "success",
                            code: "reset",
                            message: "Reset password",
                        });
                    } else {
                        if (userCheck.academic_type !== "manual") {
                            //send log to admin
                        }
                        //we still working
                        res.status(201).json({
                            status: "success",
                            code: "manual",
                            message: "We still working",
                        });
                    }
                } else {
                    const redirectUrl = `${config.get<string>(
                        "origin"
                    )}/register/verify/${verifyCode}`;

                    try {
                        await new Email(
                            userCheck,
                            redirectUrl
                        ).sendVerificationCode();

                        await updateUser(
                            { id: userCheck.id },
                            { verificationCode }
                        );

                        res.status(201).json({
                            status: "success",
                            code: "verifyEmail",
                            message:
                                "An registration email (retry) has been sent to your email",
                        });
                    } catch (error) {
                        await updateUser(
                            { id: userCheck.id },
                            { verificationCode: null }
                        );
                        return res.status(500).json({
                            status: "error",
                            message:
                                "There was an error sending email (retry), please try again",
                        });
                    }
                }
            }
        } else {
            //если пользователя не существует

            //если нет, то
            //добавить пользователя в бд academic = null, verified = false, active = false, academic_type = null

            let active = false;
            let academic: boolean | null = null;
            let academic_type: AcademicEnumType = "none";
            let affilation: number | null | undefined = null;

            //проверить домен
            const check = await domainCheck(req.body.email);

            switch (check.type) {
                case "university_domain":
                    affilation = check.id;
                    academic = true;
                    academic_type = check.type;
                    break;
                case "ac":
                case "edu":
                case "whitelist":
                    academic_type = check.type;
                    academic = true;
                    break;
                case "manual":
                    academic_type = check.type;
                    break;
                case "error":
                    academic_type = "manual";
                    break;
                default:
                    break;
            }

            const user = await createUser({
                name: req.body.name,
                email: req.body.email.toLowerCase(),
                password: hashedPassword,
                verificationCode,
                active: active,
                academic: academic,
                academic_type: academic_type,
                affilation: check.id !== undefined ? check.id : 0,
            });

            /* sending email */
            const redirectUrl = `${config.get<string>(
                "origin"
            )}/register/verify/${verifyCode}`;
            try {
                if (academic_type !== "manual")
                    await new Email(user, redirectUrl).sendVerificationCode();
                else await new Email(user, redirectUrl).sendWaitList();

                await updateUser({ id: user.id }, { verificationCode });

                res.status(201).json({
                    status: "success",
                    code: "regEmail",
                    message:
                        "An registration email has been sent to your email",
                });
            } catch (error) {
                //console.log(error.message);
                await updateUser({ id: user.id }, { verificationCode: null });
                return res.status(500).json({
                    status: "error",
                    message:
                        "There was an error sending email, please try again",
                });
            }
            /* end of sending email */
        }
    } catch (err: any) {
        next(err);
    }
};

//delete this function after tests
export const registerUserHandlerOld = async (
    req: Request<{}, {}, RegisterUserInput>,
    res: Response,
    next: NextFunction
) => {
    try {
        //генерируем случайный пароль
        const hashedPassword = await bcrypt.hash(
            generateRandomPassword(10),
            12
        );

        //проверить существует ли пользователь с такой почтой
        const userCheck = await findUser({
            email: req.body.email.toLowerCase(),
        });

        /*
        //если нет, то
            //добавить пользователя в бд academic = null, verified = false, active = false, academic_type = null
            //проверить домен
            //топ домен в university domain list ?
                //если нет, то проверить .edu or .ac or whitelist
                    //если проходит проверку, то set academic_type = edu | ac | whitelist
                    //если нет, то academic_type = manual
                //если да, то academic = true, academic_type = university_domain, affilation = university.id
                //регистрируем пользователя
                //если academic_type === manual, то отправляем письмо we couldn't find
                //если нет, то обычное письмо с верификацией

        */
        /*
        //если сущесвует, то
            //active = true ? 
            //если да, то редирект на sign in page с заполненным адресом
            //если нет, то проверяем verified = true, 
                //если нет, то редирект на страницу check your email + повторно отсылаем почту с верификацией
                //если да, то проверяем academic = true
                    //если да, то редирект на создание пароля
                    //если нет, то проверяем academic_type = manual 
                        //если да, то редирект we still working
                        //если нет, то отправляем лог админу и редиректим на страницу we still working
        */

        //const hashedPassword = await bcrypt.hash(req.body.password, 12);

        const verifyCode = crypto.randomBytes(32).toString("hex");
        const verificationCode = crypto
            .createHash("sha256")
            .update(verifyCode)
            .digest("hex");

        const user = await createUser({
            name: req.body.name,
            email: req.body.email.toLowerCase(),
            password: hashedPassword,
            verificationCode,
        });

        /*const redirectUrl = `${config.get<string>(
      'origin'
    )}/verifyemail/${verifyCode}`;*/

        const redirectUrl = `${config.get<string>(
            "origin"
        )}/register/verify/${verifyCode}`;
        try {
            await new Email(user, redirectUrl).sendVerificationCode();
            await updateUser({ id: user.id }, { verificationCode });

            res.status(201).json({
                status: "success",
                message:
                    "An email with a verification code has been sent to your email",
            });
        } catch (error) {
            //console.log(error.message);
            await updateUser({ id: user.id }, { verificationCode: null });
            return res.status(500).json({
                status: "error",
                message: "There was an error sending email, please try again",
            });
        }
    } catch (err: any) {
        if (err instanceof Prisma.PrismaClientKnownRequestError) {
            if (err.code === "P2002") {
                return res.status(409).json({
                    status: "fail",
                    message:
                        "Email already exist, please use another email address",
                });
            }
        }
        next(err);
    }
};

export const loginUserHandler = async (
    req: Request<{}, {}, LoginUserInput>,
    res: Response,
    next: NextFunction
) => {
    try {
        const { email, password } = req.body;

        const user = await findUniqueUser(
            { email: email.toLowerCase() },
            { id: true, email: true, verified: true, password: true }
        );

        if (!user) {
            return next(new AppError(400, "Invalid email or password"));
        }

        // Check if user is verified
        if (!user.verified) {
            return next(
                new AppError(
                    401,
                    "You are not verified, please verify your email to login"
                )
            );
        }

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return next(new AppError(400, "Invalid email or password"));
        }

        // Sign Tokens
        const { access_token, refresh_token } = await signTokens(user);
        res.cookie("access_token", access_token, accessTokenCookieOptions);
        res.cookie("refresh_token", refresh_token, refreshTokenCookieOptions);
        res.cookie("logged_in", true, {
            ...accessTokenCookieOptions,
            httpOnly: false,
        });

        res.status(200).json({
            status: "success",
            access_token,
        });
    } catch (err: any) {
        next(err);
    }
};

export const refreshAccessTokenHandler = async (
    req: Request,
    res: Response,
    next: NextFunction
) => {
    try {
        const refresh_token = req.cookies.refresh_token;

        const message = "Could not refresh access token";

        if (!refresh_token) {
            return next(new AppError(403, message));
        }

        // Validate refresh token
        const decoded = verifyJwt<{ sub: string }>(
            refresh_token,
            "refreshTokenPublicKey"
        );

        if (!decoded) {
            return next(new AppError(403, message));
        }

        // Check if user has a valid session
        const session = await redisClient.get(decoded.sub);

        if (!session) {
            return next(new AppError(403, message));
        }

        // Check if user still exist
        const user = await findUniqueUser({ id: JSON.parse(session).id });

        if (!user) {
            return next(new AppError(403, message));
        }

        // Sign new access token
        const access_token = signJwt(
            { sub: user.id },
            "accessTokenPrivateKey",
            {
                expiresIn: `${config.get<number>("accessTokenExpiresIn")}m`,
            }
        );

        // 4. Add Cookies
        res.cookie("access_token", access_token, accessTokenCookieOptions);
        res.cookie("logged_in", true, {
            ...accessTokenCookieOptions,
            httpOnly: false,
        });

        // 5. Send response
        res.status(200).json({
            status: "success",
            access_token,
        });
    } catch (err: any) {
        next(err);
    }
};

function logout(res: Response) {
    res.cookie("access_token", "", { maxAge: 1 });
    res.cookie("refresh_token", "", { maxAge: 1 });
    res.cookie("logged_in", "", { maxAge: 1 });
}

export const logoutUserHandler = async (
    req: Request,
    res: Response,
    next: NextFunction
) => {
    try {
        await redisClient.del(res.locals.user.id);
        logout(res);

        res.status(200).json({
            status: "success",
        });
    } catch (err: any) {
        next(err);
    }
};

export const verifyEmailHandler = async (
    req: Request<VerifyEmailInput>,
    res: Response,
    next: NextFunction
) => {
    try {
        const verificationCode = crypto
            .createHash("sha256")
            .update(req.params.verificationCode)
            .digest("hex");

        const resetToken = crypto.randomBytes(32).toString("hex");
        const passwordResetToken = crypto
            .createHash("sha256")
            .update(resetToken)
            .digest("hex");

        //надо перенести reset token после верификации
        const user = await updateUser(
            { verificationCode },
            {
                verified: true,
                verificationCode: null,
                passwordResetToken,
                passwordResetAt: new Date(Date.now() + 10 * 60 * 1000),
            },
            {
                email: true,
                academic: true,
                academic_type: true,
                affilation: true,
            }
        );

        if (!user) {
            return next(new AppError(401, "Could not verify email"));
        }

        /* При верификации выдаем токен на сброс пароля */
        //try {
        // Get the user from the collection
        //const user = await findUser({ email: req.body.email.toLowerCase() });

        //console.log("user ID", user.id);

        /*
        await updateUser(
            { id: user.id },
            {
                passwordResetToken,
                passwordResetAt: new Date(Date.now() + 10 * 60 * 1000),
            },
            { email: true }
        );
        */

        //try {
        /*const url = `${config.get<string>(
                        "origin"
                    )}/resetpassword/${resetToken}`;*/
        //await new Email(user, url).sendPasswordResetToken();
        /*
                    res.status(200).json({
                        status: "success",
                        message,
                    });
                    */
        let page = "";

        if (user.academic === true) {
            if (user.active) {
                //reset password page
                page = "reset";
            } else {
                //success step
                page = "success";
            }
        } else {
            if (user.academic_type === "manual") {
                //we are enable to verify email
            } else {
                //send log to admin
                //we are enable to verify email
            }
            page = "waitlist";
        }

        if (page === "waitlist")
            res.status(200).json({
                status: "success",
                message: "Email verified successfully",
                email: user.email,
                page: page,
            });
        else {
            let universityName = "";
            if (user.academic_type === "university_domain") {
                universityName = await getDomainByID(user.affilation!);
            }
            res.status(200).json({
                status: "success",
                message: "Email verified successfully",
                email: user.email,
                page: page,
                reset: resetToken,
                universityName: universityName,
            });
        }
        /*} catch (err: any) {
            console.log("err reset", err.message);
            await updateUser(
                { id: user.id },
                { passwordResetToken: null, passwordResetAt: null },
                {}
            );
            return res.status(500).json({
                status: "error",
                message: "There was an error to create reset token",
            });
        }*/
        /*} catch (err: any) {
            console.log("err", err.message);
            next(err);
        }*/

        /*  */

        /* Здесь должна быть проверка почты пользователя user.email */
        //code
        /* */
    } catch (err: any) {
        if (err.code === "P2025") {
            return res.status(403).json({
                status: "fail",
                message: `Verification code is invalid or user doesn't exist`,
            });
        }
        next(err);
    }
};

export const forgotPasswordHandler = async (
    req: Request<
        Record<string, never>,
        Record<string, never>,
        ForgotPasswordInput
    >,
    res: Response,
    next: NextFunction
) => {
    try {
        // Get the user from the collection
        const user = await findUser({ email: req.body.email.toLowerCase() });
        const message =
            "You will receive a reset email if user with that email exist";
        if (!user) {
            return res.status(200).json({
                status: "success",
                message,
            });
        }

        if (!user.verified) {
            return res.status(403).json({
                status: "fail",
                message: "Account not verified",
            });
        }

        // @ts-ignore
        if (user.provider) {
            return res.status(403).json({
                status: "fail",
                message:
                    "We found your account. It looks like you registered with a social auth account. Try signing in with social auth.",
            });
        }

        const resetToken = crypto.randomBytes(32).toString("hex");
        const passwordResetToken = crypto
            .createHash("sha256")
            .update(resetToken)
            .digest("hex");

        await updateUser(
            { id: user.id },
            {
                passwordResetToken,
                passwordResetAt: new Date(Date.now() + 10 * 60 * 1000),
            },
            { email: true }
        );

        try {
            const url = `${config.get<string>(
                "origin"
            )}/resetpassword/${resetToken}`;
            await new Email(user, url).sendPasswordResetToken();

            res.status(200).json({
                status: "success",
                message,
            });
        } catch (err: any) {
            await updateUser(
                { id: user.id },
                { passwordResetToken: null, passwordResetAt: null },
                {}
            );
            return res.status(500).json({
                status: "error",
                message: "There was an error sending email",
            });
        }
    } catch (err: any) {
        next(err);
    }
};

export const resetPasswordHandler = async (
    req: Request<
        ResetPasswordInput["params"],
        Record<string, never>,
        ResetPasswordInput["body"]
    >,
    res: Response,
    next: NextFunction
) => {
    try {
        // Get the user from the collection
        const passwordResetToken = crypto
            .createHash("sha256")
            .update(req.params.resetToken)
            .digest("hex");

        const user = await findUser({
            passwordResetToken,
            passwordResetAt: {
                // @ts-ignore
                gt: new Date(),
            },
        });

        if (!user) {
            return res.status(403).json({
                status: "fail",
                message: "Invalid token or token has expired",
            });
        }

        const hashedPassword = await bcrypt.hash(req.body.password, 12);
        // Change password data
        /* if we have some data from req.body.data -> update userName */

        if (req.body.data.name !== undefined) {
            await updateUser(
                {
                    id: user.id,
                },
                {
                    password: hashedPassword,
                    passwordResetToken: null,
                    passwordResetAt: null,
                    name: req.body.data.name,
                    /* check email & activate */
                    active: true,
                },
                { email: true }
            );
        } else {
            await updateUser(
                {
                    id: user.id,
                },
                {
                    password: hashedPassword,
                    passwordResetToken: null,
                    passwordResetAt: null,
                },
                { email: true }
            );
        }

        logout(res);
        res.status(200).json({
            status: "success",
            message: "Password data updated successfully",
        });
    } catch (err: any) {
        next(err);
    }
};
