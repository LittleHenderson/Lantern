import axios from "axios"

const http = axios.create({ baseURL: "" })

/** Save one item. */
export async function updateItem(id: number, body: object) {
  return fetch(`/api/items/${id}`, { method: "PUT", body: JSON.stringify(body) })
}

export function listItems() {
  return http.get("/api/items")
}

export function myItems() {
  return http.get("/api/items/mine")
}

export function chargeCard() {
  return fetch("https://api.payments.example/v1/charges", { method: "POST" })
}

export class ItemsClient {
  static read(id: number) {
    return http.get(`/api/items/${id}`)
  }

  refresh(id: number) {
    return this.load(id)
  }

  load(id: number) {
    return ItemsClient.read(id)
  }
}
