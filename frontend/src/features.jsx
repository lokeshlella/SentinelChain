import { createContext, useContext, useEffect, useState } from 'react'
import { api } from './api/client.js'
import { UNKNOWN_BUILD, normaliseFeatures } from './utils/features.js'

const FeaturesContext = createContext(UNKNOWN_BUILD)

// Loads the build's features once. While the backend is starting (network error / 5xx) it retries;
// an answer that is not a feature list leaves every Phase-2 feature hidden.
export function FeaturesProvider({ children }) {
  const [build, setBuild] = useState(UNKNOWN_BUILD)

  useEffect(() => {
    let cancelled = false
    let timer = null
    const load = () => {
      api.get('/features')
        .then((data) => { if (!cancelled) setBuild(normaliseFeatures(data)) })
        .catch((error) => {
          if (cancelled) return
          if (error.status === 0 || error.status >= 500) timer = setTimeout(load, 3000)
          else console.warn('Sentinel Chain: /api/features unavailable; Phase-2 features stay hidden', error.message)
        })
    }
    load()
    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [])

  return <FeaturesContext.Provider value={build}>{children}</FeaturesContext.Provider>
}

export function useFeatures() {
  return useContext(FeaturesContext)
}
