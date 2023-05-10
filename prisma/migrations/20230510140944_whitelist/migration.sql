-- CreateTable
CREATE TABLE "Whitelist" (
    "id" SERIAL NOT NULL,
    "email" TEXT NOT NULL,
    "comment" TEXT,

    CONSTRAINT "Whitelist_pkey" PRIMARY KEY ("id")
);
