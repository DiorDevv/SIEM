import { Component } from 'react'

export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error }
  }

  componentDidCatch(error, info) {
    console.error('UI error caught by boundary:', error, info.componentStack)
  }

  render() {
    if (!this.state.hasError) return this.props.children

    return (
      <div
        className="flex flex-col items-center justify-center h-screen gap-4"
        style={{ background: 'var(--bg-primary)', color: 'var(--text-primary)' }}
      >
        <div className="text-5xl">⚠</div>
        <h1 className="text-2xl font-bold">Something went wrong</h1>
        <p className="text-sm opacity-60 max-w-md text-center">
          {this.state.error?.message || 'An unexpected error occurred in the UI.'}
        </p>
        <button
          className="mt-2 px-4 py-2 rounded bg-blue-600 hover:bg-blue-700 text-white text-sm"
          onClick={() => {
            this.setState({ hasError: false, error: null })
            window.location.href = '/'
          }}
        >
          Return to Dashboard
        </button>
      </div>
    )
  }
}
