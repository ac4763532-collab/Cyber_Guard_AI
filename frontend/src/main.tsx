import React from 'react'
import ReactDOM from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter } from 'react-router-dom'
import { AuthProvider } from '@/contexts/AuthContext'
import { ToastProvider, KeyboardShortcutsProvider } from '@/components/ui'
import { AlertNotificationProvider } from '@/contexts/AlertNotificationContext'
import { AlertPopup } from '@/components/AlertPopup/AlertPopup'
import App from './App'
import './index.css'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30000, // 30 seconds
      retry: 1,
    },
  },
})

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AuthProvider>
          <ToastProvider>
            <KeyboardShortcutsProvider>
              {/* AlertNotificationProvider needs AuthProvider above it
                  (useAlertSocket reads the JWT via useAuth) and must wrap
                  App so AlertPopup, mounted once here (not per-page, like
                  ToastProvider's own toasts), can render over every
                  route. */}
              <AlertNotificationProvider>
                <App />
                <AlertPopup />
              </AlertNotificationProvider>
            </KeyboardShortcutsProvider>
          </ToastProvider>
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>,
)
