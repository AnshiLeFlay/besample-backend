-- CreateTable
CREATE TABLE "Universities" (
    "Alpha2code" TEXT,
    "Country" TEXT,
    "Domains" TEXT,
    "Name" TEXT,
    "WebPages" TEXT,
    "id" SERIAL NOT NULL,

    CONSTRAINT "Universities_pkey" PRIMARY KEY ("id")
);
