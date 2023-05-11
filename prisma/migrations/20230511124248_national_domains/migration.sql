-- CreateTable
CREATE TABLE "NationalDomains" (
    "id" SERIAL NOT NULL,
    "country" TEXT NOT NULL,
    "domain" TEXT NOT NULL,

    CONSTRAINT "NationalDomains_pkey" PRIMARY KEY ("id")
);
