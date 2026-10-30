import { getSessionUser } from "@/lib/auth"
import { insertTodo } from "@/lib/db"

export async function GET() {
  return Response.json([])
}

export async function POST(req: Request) {
  const user = await getSessionUser(req)
  if (!user) return new Response("unauthorized", { status: 401 })
  const { title } = await req.json()
  await insertTodo(title, user.id)
  return Response.json({ ok: true })
}
