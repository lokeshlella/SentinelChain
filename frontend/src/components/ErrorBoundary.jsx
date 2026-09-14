import { Component } from 'react'
import { Link } from 'react-router-dom'

// Last line of defence: a render error in one page shows a message instead of a blank screen.
export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { error: null }
  }

  static getDerivedStateFromError(error) {
    return { error }
  }

  componentDidUpdate(prevProps) {
    if (prevProps.children !== this.props.children && this.state.error) this.setState({ error: null })
  }

  render() {
    if (this.state.error) {
      return (
        <div className="alert error">
          <strong>The page failed to render:</strong> {String(this.state.error?.message || this.state.error)}
          <div><Link to="/" onClick={() => this.setState({ error: null })}>Back to the dashboard</Link></div>
        </div>
      )
    }
    return this.props.children
  }
}
