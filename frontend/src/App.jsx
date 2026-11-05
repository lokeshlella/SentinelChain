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
import Loading from './components/Loading.jsx'
import { useFeatures } from './features.jsx'

function NotFound() {
  return (
    <div>
      <h1>Page not found</h1>
      <p className="muted">There is nothing at this address. <Link to="/">Back to the dashboard</Link>.</p>
    </div>
  )
}

// A page of a feature this build does not expose is "not found"; until the build is known, wait.
function Gate({ feature, children }) {
  const { loaded, features } = useFeatures()
  if (!loaded) return <Loading text="Loading…" />
  return features[feature] ? children : <NotFound />
}

export default function App() {
  const { phase, features } = useFeatures()
  return (
    <div className="layout">
      <header className="topbar">
        <div className="brand">
          <Link to="/" className="brand-link"><span className="brand-mark">◆</span> Sentinel Chain</Link>
          <span className="brand-sub">Agentic AI for Secure Software Supply Chains{phase === 1 ? ' · Phase 1' : phase === 2 ? ' · V1' : ''}</span>
        </div>
        <nav>
          <NavLink to="/" end>Dashboard</NavLink>
          {features.pull_requests && <NavLink to="/pull-requests">Pull requests</NavLink>}
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
            <Route path="/remediations/:id" element={<Gate feature="remediation"><Remediation /></Gate>} />
            <Route path="/validations/:id" element={<Gate feature="validation"><Validation /></Gate>} />
            <Route path="/pull-requests" element={<Gate feature="pull_requests"><PullRequests /></Gate>} />
            <Route path="/pull-requests/:id" element={<Gate feature="pull_requests"><PullRequest /></Gate>} />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </ErrorBoundary>
      </main>
      <footer className="footer muted">
        {features.ai
          ? 'Sentinel Chain V1 — findings are facts from OSV and source scans; AI sections are model inferences and are labelled as such.'
          : 'Sentinel Chain — findings are facts from OSV.dev and deterministic source scans.'}
      </footer>
    </div>
  )
}
