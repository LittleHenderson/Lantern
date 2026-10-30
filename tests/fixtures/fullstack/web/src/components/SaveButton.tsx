import { updateItem, format } from "@/lib"
import * as lib from "../lib/api"

type Props = { id: number }

export function SaveButton({ id }: Props) {
  const onSave = async () => {
    await updateItem(id, { price: format(1) })
  }
  const refresh = () => new lib.ItemsClient().refresh(id)
  return <button onClick={onSave} onDoubleClick={refresh}>Save</button>
}
