import { BrowserRouter, Route, Routes } from "react-router-dom"
import UserPage from "@/pages/UserPage"
import Admin from "@/pages/Admin"

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/users/:id" element={<UserPage />} />
        <Route path="/admin" element={<Admin />} />
      </Routes>
    </BrowserRouter>
  )
}
