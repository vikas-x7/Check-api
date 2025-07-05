import { PrismaClient } from '@prisma/client'
const prisma = new PrismaClient()
async function main() {
  const projects = await prisma.project.findMany()
  console.log("PROJECTS:")
  console.log(JSON.stringify(projects, null, 2))
}
main().catch(e => console.error(e)).finally(() => prisma.$disconnect())
