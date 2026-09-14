import { Routes, Route, NavLink, Link } from 'react-router-dom'
import Dashboard from './pages/Dashboard.jsx'
import Health from './pages/Health.jsx'
import Repository from './pages/Repository.jsx'
import Analysis from './pages/Analysis.jsx'
import Finding from './pages/Finding.jsx'
import Remediation from './pages/Remediation.jsx'
import Validation from './pages/Validation.jsx'
import PullRequest from './pages/PullRequest.jsx'
import PullRequests from './pages/PullRequests.jsx'
import ErrorBoundary from './components/ErrorBoundary.jsx'

function NotFound() {
  return (
    <div>
      <h1>Page not found</h1>
      <p className="muted">There is nothing at this address. <Link to="/">Back to the dashboard</Link>.</p>
    </div>
  )
}

export default function App() {
  return (
    <div className="layout">
      <header className="topbar">
        <div className="brand">
          <Link to="/" className="brand-link"><span className="brand-mark">◆</span> Sentinel Chain</Link>
          <span className="brand-sub">Agentic AI for Secure Software Supply Chains · V1</span>
        </div>
        <nav>
          <NavLink to="/" end>Dashboard</NavLink>
          <NavLink to="/pull-requests">Pull requests</NavLink>
          <NavLink to="/health">System health</NavLink>
        </nav>
      </header>
      <main className="content">
        <ErrorBoundary>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/health" element={<Health />} />
            <Route path="/repositories/:id" element={<Repository />} />
            <Route path="/analyses/:id" element={<Analysis />} />
            <Route path="/findings/:id" element={<Finding />} />
            <Route path="/remediations/:id" element={<Remediation />} />
            <Route path="/validations/:id" element={<Validation />} />
            <Route path="/pull-requests" element={<PullRequests />} />
            <Route path="/pull-requests/:id" element={<PullRequest />} />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </ErrorBoundary>
      </main>
      <footer className="footer muted">Sentinel Chain V1 — findings are facts from OSV and source scans; AI sections are model inferences and are labelled as such.</footer>
    </div>
  )
}
