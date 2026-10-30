import { useEffect, useState } from "react"
import { getUser } from "@/api"
import Bio from "@/components/Bio"

export default function UserPage({ id }: { id: string }) {
  const [user, setUser] = useState<any>(null)
  useEffect(() => {
    getUser(id).then(setUser)
  }, [id])
  return <div>{user && <Bio html={user.bio} />}</div>
}
