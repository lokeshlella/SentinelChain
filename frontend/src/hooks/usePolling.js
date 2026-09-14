import { useCallback, useEffect, useRef, useState } from 'react'

/**
 * Fetch data once and keep re-fetching every `interval` ms while `shouldContinue(data)` returns true.
 * Returns { data, error, loading, reload, setData }.
 *
 *   const { data, error, loading, reload } = usePolling(
 *     () => api.get(`/analyses/${id}`), 3000, (a) => a.status === 'PENDING' || a.status === 'RUNNING', [id])
 */
export default function usePolling(fetchFn, interval, shouldContinue, deps = []) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)
  const [tick, setTick] = useState(0)
  const latest = useRef(null)
  const timer = useRef(null)

  const reload = useCallback(() => setTick((t) => t + 1), [])

  useEffect(() => {
    let cancelled = false
    const keepGoing = (value) =>
      typeof shouldContinue === 'function' ? !!shouldContinue(value) : !!shouldContinue

    async function run() {
      try {
        const next = await fetchFn()
        if (cancelled) return
        latest.current = next
        setData(next)
        setError(null)
        setLoading(false)
        if (keepGoing(next) && interval > 0) timer.current = setTimeout(run, interval)
      } catch (e) {
        if (cancelled) return
        setError(e)
        setLoading(false)
        // Keep polling through transient failures (network / 5xx) when something was already loaded.
        const transient = e && (e.status === 0 || e.status >= 500)
        if (latest.current !== null && transient && keepGoing(latest.current) && interval > 0) {
          timer.current = setTimeout(run, interval)
        }
      }
    }

    setLoading(true)
    run()
    return () => {
      cancelled = true
      clearTimeout(timer.current)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tick, interval, ...deps])

  const setBoth = useCallback((value) => {
    latest.current = value
    setData(value)
  }, [])

  return { data, error, loading, reload, setData: setBoth }
}
