import { SaveButton } from "../components/SaveButton"
import { listItems, myItems } from "@/lib/api"

export default function ItemsPage() {
  listItems()
  myItems()
  return <SaveButton id={1} />
}
