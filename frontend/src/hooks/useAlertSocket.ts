/**
 * CyberGuard AI - Real-time alert WebSocket hook
 *
 * Connects to the authenticated, tenant-scoped /api/v1/ws endpoint (see
 * app/api/v1/ws.py + app/websocket/auth.py) and surfaces new/updated
 * alerts to AlertNotificationContext.
 *
 * Responsibilities kept deliberately narrow:
 * - Authenticate the WS upgrade with the current JWT (query param, since
 *   browsers can't set a custom header on a WS upgrade).
 * - Reconnect with exponential backoff + jitter on drop.
 * - On every (re)connect, call GET /alerts/recent to recover anything
 *   created while disconnected - the WS channel alone cannot replay
 *   missed messages, since ConnectionManager has no backlog/queue.
 * - Deduplicate by the alert's own persisted id (never a frontend-
 *   generated id) so a reconnect, a redelivered WS message, or an
 *   overlapping recent-alerts fetch never re-fires the same popup/siren
 *   twice. Dedup state lives in sessionStorage - deliberately NOT
 *   localStorage: "don't replay the siren for an alert I've already
 *   seen THIS SESSION" is the right scope. A brand new tab/session
 *   should still be able to hear about a still-open critical alert.
 *
 * This hook does not decide whether to show a popup or play a sound -
 * that's AlertNotificationContext's job, driven by user preferences from
 * useNotificationPreferences. This hook only guarantees: every eligible,
 * persisted alert reaches the caller's onAlert callback exactly once per
 * browser session.
 */

import { useCallback, useEffect, useRef } from 'react'
import { useAuth } from '@/contexts/AuthContext'
import { alertsApi, wsApi } from '@/services/api'

export interface RealtimeAlert {
  alertId: string
  title: string
  severity: string
  category?: string
  summary?: string
  riskScore?: number
  createdAt: string
  /** 'new_alert' | 'alert_updated' - see WSEventType in
   * app/websocket/events.py. Only alert-shaped events reach onAlert;
   * anything else is ignored by this hook. */
  eventType: string
}

const SEEN_ALERTS_KEY = 'cyberguard.seenAlertIds'
const LAST_SEEN_TIMESTAMP_KEY = 'cyberguard.lastAlertTimestamp'
const MAX_SEEN_IDS = 500

function loadSeenIds(): Set<string> {
  try {
    const raw = sessionStorage.getItem(SEEN_ALERTS_KEY)
    if (!raw) return new Set()
    return new Set(JSON.parse(raw))
  } catch {
    return new Set()
  }
}

function saveSeenIds(ids: Set<string>): void {
  try {
    // Cap growth - keep the most recently added ids only. Order isn't
    // preserved by Set, but this is a soft cap for memory, not a strict
    // LRU; exact-correctness of *which* old ids get dropped doesn't
    // matter since a dropped id just means that one alert could in
    // theory re-notify after a very long session, which is harmless.
    const arr = Array.from(ids)
    const trimmed = arr.length > MAX_SEEN_IDS ? arr.slice(arr.length - MAX_SEEN_IDS) : arr
    sessionStorage.setItem(SEEN_ALERTS_KEY, JSON.stringify(trimmed))
  } catch {
    // sessionStorage unavailable (private mode edge cases) - dedup
    // degrades to in-memory-only for this hook instance, which is still
    // correct within a single mount, just not across remounts.
  }
}

function getLastSeenTimestamp(): string | null {
  try {
    return sessionStorage.getItem(LAST_SEEN_TIMESTAMP_KEY)
  } catch {
    return null
  }
}

function setLastSeenTimestamp(iso: string): void {
  try {
    sessionStorage.setItem(LAST_SEEN_TIMESTAMP_KEY, iso)
  } catch {
    // Non-fatal - see loadSeenIds's catch.
  }
}

const ALERT_EVENT_TYPES = new Set(['new_alert', 'alert_updated'])

export function useAlertSocket(onAlert: (alert: RealtimeAlert) => void) {
  const { getToken, isAuthenticated } = useAuth()
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectAttemptRef = useRef(0)
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const seenIdsRef = useRef<Set<string>>(loadSeenIds())
  const closedByUsRef = useRef(false)
  const onAlertRef = useRef(onAlert)
  onAlertRef.current = onAlert

  const emitIfUnseen = useCallback((alert: RealtimeAlert) => {
    if (seenIdsRef.current.has(alert.alertId)) {
      return
    }
    seenIdsRef.current.add(alert.alertId)
    saveSeenIds(seenIdsRef.current)
    if (alert.createdAt) {
      setLastSeenTimestamp(alert.createdAt)
    }
    onAlertRef.current(alert)
  }, [])

  /** Recover alerts created while disconnected (or before this tab ever
   * connected). Always runs on (re)connect - cheap, and the real
   * dedup/correctness guarantee is emitIfUnseen's id check, not whether
   * this fetch itself is "needed". */
  const recoverMissedAlerts = useCallback(async () => {
    try {
      const since = getLastSeenTimestamp() || undefined
      const alerts = await alertsApi.getRecent({ since, limit: 100 })
      for (const alert of alerts) {
        emitIfUnseen({
          alertId: alert.id,
          title: alert.title,
          severity: alert.severity,
          category: alert.category,
          summary: alert.description,
          riskScore: alert.risk_score,
          createdAt: alert.created_at,
          eventType: 'new_alert',
        })
      }
    } catch {
      // Best-effort recovery - a failure here (e.g. transient 401 during
      // token refresh) must not crash the socket lifecycle. The next
      // reconnect will try again.
    }
  }, [emitIfUnseen])

  const scheduleReconnect = useCallback((connectFn: () => void) => {
    if (closedByUsRef.current) return
    const attempt = reconnectAttemptRef.current
    // Exponential backoff with jitter, capped at 30s, so a server outage
    // doesn't produce a reconnect storm across many open tabs.
    const base = Math.min(30000, 1000 * 2 ** attempt)
    const jitter = Math.random() * 0.4 * base
    const delay = base + jitter
    reconnectAttemptRef.current = attempt + 1
    reconnectTimeoutRef.current = setTimeout(connectFn, delay)
  }, [])

  useEffect(() => {
    if (!isAuthenticated) {
      return
    }

    closedByUsRef.current = false

    const connect = async () => {
      if (closedByUsRef.current) return

      const token = await getToken()
      if (!token) {
        // Not actually authenticated yet (token still loading) - retry
        // shortly rather than connecting unauthenticated and getting a
        // 4401 close.
        scheduleReconnect(connect)
        return
      }

      const ws = wsApi.connect(['alerts'], token)
      wsRef.current = ws

      ws.onopen = () => {
        reconnectAttemptRef.current = 0
        void recoverMissedAlerts()
      }

      ws.onmessage = (event) => {
        let payload: any
        try {
          payload = JSON.parse(event.data)
        } catch {
          return
        }

        const eventType = payload?.type
        if (!eventType) return

        if (ALERT_EVENT_TYPES.has(eventType)) {
          const data = payload.data || {}
          if (!data.alert_id) return
          emitIfUnseen({
            alertId: data.alert_id,
            title: data.title,
            severity: payload.severity || data.severity,
            category: data.category,
            summary: data.summary,
            riskScore: data.risk_score,
            createdAt: payload.timestamp,
            eventType,
          })
        }
      }

      ws.onclose = (event) => {
        wsRef.current = null
        if (event.code === 4401) {
          // Auth rejected - the token is invalid/expired. Reconnecting
          // immediately would just loop; back off normally and let the
          // next attempt pick up a fresh token via getToken().
        }
        scheduleReconnect(connect)
      }

      ws.onerror = () => {
        // The browser also fires onclose after onerror for a WebSocket;
        // reconnect scheduling happens there, not here, to avoid
        // double-scheduling.
      }
    }

    void connect()

    return () => {
      closedByUsRef.current = true
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current)
      }
      wsRef.current?.close()
      wsRef.current = null
    }
  }, [isAuthenticated, getToken, emitIfUnseen, recoverMissedAlerts, scheduleReconnect])
}
