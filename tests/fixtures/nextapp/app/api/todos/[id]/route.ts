import { deleteTodo } from "@/lib/db"

export async function GET(_req: Request, { params }: { params: { id: string } }) {
  return Response.json({ id: params.id, title: "x" })
}

// planted: deletes without checking who is asking
export async function DELETE(_req: Request, { params }: { params: { id: string } }) {
  await deleteTodo(params.id)
  return Response.json({ ok: true })
}
