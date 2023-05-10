-- CreateEnum
CREATE TYPE "AcademicEnumType" AS ENUM ('none', 'ac', 'edu', 'whitelist', 'manual', 'university_domain');

-- AlterTable
ALTER TABLE "users" ADD COLUMN     "academic" BOOLEAN,
ADD COLUMN     "academic_type" "AcademicEnumType" DEFAULT E'none';
