"use client"
import { useState } from "react"

export default function TodoList() {
  const [title, setTitle] = useState("")

  async function addTodo() {
    await fetch("/api/todos", { method: "POST", body: JSON.stringify({ title }) })
  }

  async function removeTodo(id: number) {
    await fetch(`/api/todos/${id}`, { method: "DELETE" })
  }

  return (
    <div>
      <input value={title} onChange={(e) => setTitle(e.target.value)} />
      <button onClick={addTodo}>Add</button>
      <button onClick={() => removeTodo(1)}>Delete first</button>
    </div>
  )
}
