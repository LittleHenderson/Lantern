export async function getSessionUser(req: Request) {
  const token = req.headers.get("authorization")
  return token ? { id: "u1" } : null
}
