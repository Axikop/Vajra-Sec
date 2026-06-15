import { Routes, Route, Navigate } from "react-router-dom";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import Lookup from "./pages/Lookup";
import FofaGpt from "./pages/FofaGpt";

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/"         element={<Dashboard />} />
        <Route path="/lookup"   element={<Lookup />} />
        <Route path="/fofa-gpt" element={<FofaGpt />} />
        <Route path="*"         element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
