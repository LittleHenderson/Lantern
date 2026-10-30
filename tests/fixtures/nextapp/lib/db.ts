import { createClient } from "@supabase/supabase-js"

export const db = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_KEY!)

export async function insertTodo(title: string, userId: string) {
  return db.from("todos").insert({ title, user_id: userId })
}

export async function deleteTodo(id: string) {
  return db.from("todos").delete().eq("id", id)
}
