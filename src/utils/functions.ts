import { PrismaClient } from "@prisma/client";

export const generateRandomPassword = (length: number) => {
    const possibleChars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
    let password = "";
    for (let i = 0; i < length; i++) {
        password += possibleChars.charAt(
            Math.floor(Math.random() * possibleChars.length)
        );
    }
    return password;
};

export const getDomainByID = async (ID: number): Promise<string> => {
    try {
        const prisma = new PrismaClient();
        const university: any = await prisma.universities.findFirst({
            where: {
                id: ID,
            },
        });

        console.log(university);

        if (university === undefined || university === null) {
            return "";
        }

        return university.Name;
    } catch (err: any) {
        return err;
    }
};

export const domainCheck = async (
    email: string
): Promise<{
    type: string;
    error?: string;
    id?: number;
    name?: string | null;
}> => {
    try {
        const [, domain] = email.split("@");
        const emailDomain = domain.split(".");

        const prisma = new PrismaClient();

        const univerDB = await prisma.universities.findMany();

        if (domain === undefined)
            return { error: "email format is invalid", type: "error" };

        for (let i = 0; i < univerDB.length; i++) {
            if (univerDB[i].Domains !== null) {
                let needleDomain = univerDB[i].Domains!.split(".");

                let findCount = 0;
                let index = emailDomain.length - 1;

                for (let i = needleDomain.length - 1; i > -1; i--) {
                    if (needleDomain[i] === emailDomain[index]) findCount++;
                    else break;
                    index--;
                }

                if (findCount === needleDomain.length)
                    return {
                        id: univerDB[i].id,
                        name: univerDB[i].Name,
                        type: "university_domain",
                    };
            }
        }

        //проверяем .ac и .edu
        if (emailDomain[emailDomain.length - 1] === "ac") return { type: "ac" };
        if (emailDomain[emailDomain.length - 1] === "edu")
            return { type: "edu" };

        //нац домены ac. и edu.

        //проверяем whitelist
        const whitelist = await prisma.whitelist.findFirst({
            where: {
                email: email,
            },
        });

        if (whitelist?.email !== undefined) {
            return { type: "whitelist" };
        }

        //если ни одна проверка не прошла ставим тип manual
        return { type: "manual" };
    } catch (err: any) {
        return { error: err.message, type: "error" };
    }
};
