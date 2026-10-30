export default async function TodoPage({ params }: { params: { id: string } }) {
  const res = await fetch(`http://localhost:3000/api/todos/${params.id}`)
  const todo = await res.json()
  return <p>{todo.title}</p>
}
