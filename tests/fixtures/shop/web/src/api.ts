import axios from "axios"

const API = "/api"

export async function getUser(id: string) {
  const res = await fetch(`${API}/users/${id}`)
  return res.json()
}

export async function runBackup(name: string) {
  return axios.post("/backup", { name })
}

export async function getWeather(city: string) {
  return fetch(`https://api.weather.example.com/v1/now?city=${city}`)
}
