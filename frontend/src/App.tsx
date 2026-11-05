/**
 * CyberGuard AI - Main App Component
 *
 * Routing and layout configuration.
 */

import { Routes, Route, Navigate } from 'react-router-dom'
import { Sidebar } from '@/components/layout/Sidebar'
import { Header } from '@/components/layout/Header'
import { DashboardPage } from '@/pages/DashboardPage'
import { AlertsPage } from '@/pages/AlertsPage'
import { IncidentsPage } from '@/pages/IncidentsPage'
import { EventsPage } from '@/pages/EventsPage'
import { ReportsPage } from '@/pages/ReportsPage'
import { SettingsPage } from '@/pages/SettingsPage'
import { LoginPage } from '@/pages/LoginPage'
import { SignupPage } from '@/pages/SignupPage'
import { ForgotPasswordPage } from '@/pages/ForgotPasswordPage'
import { VerifyEmailPage } from '@/pages/VerifyEmailPage'
import { PhoneLoginPage } from '@/pages/PhoneLoginPage'
import { EmailAnalysisPage } from '@/pages/EmailAnalysisPage'
import { LogAnalysisPage } from '@/pages/LogAnalysisPage'
import { NetworkAnalysisPage } from '@/pages/NetworkAnalysisPage'
import { AgentsPage } from '@/pages/AgentsPage'
import { CorrelationPage } from '@/pages/CorrelationPage'
import { ThreatIntelPage } from '@/pages/ThreatIntelPage'
import { FeedbackPage } from '@/pages/FeedbackPage'
import { TrainingPage } from '@/pages/TrainingPage'
import { useAuth } from '@/contexts/AuthContext'

// Loading spinner component
function LoadingScreen() {
  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center">
      <div className="text-center">
        <div className="w-12 h-12 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
        <p className="text-slate-400">Loading CyberGuard AI...</p>
      </div>
    </div>
  )
}

// Protected route wrapper
function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, loading } = useAuth()

  // Show loading while checking auth
  if (loading) {
    return <LoadingScreen />
  }

  // Not authenticated -> login
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />
  }

  // Firebase: require email verification (optional - can be enabled)
  // Uncomment the following to enforce email verification:
  // if (isFirebaseEnabled && user && !user.emailVerified && user.provider === 'email') {
  //   return <Navigate to="/verify-email" replace />
  // }

  return <>{children}</>
}

// Public route wrapper (redirects to dashboard if already logged in)
function PublicRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, loading } = useAuth()

  if (loading) {
    return <LoadingScreen />
  }

  if (isAuthenticated) {
    return <Navigate to="/" replace />
  }

  return <>{children}</>
}

// Main layout with sidebar
function MainLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-screen bg-slate-950">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <Header />
        <main className="flex-1 overflow-y-auto bg-slate-950">
          {children}
        </main>
      </div>
    </div>
  )
}

function App() {
  return (
    <Routes>
      {/* Public auth routes */}
      <Route
        path="/login"
        element={
          <PublicRoute>
            <LoginPage />
          </PublicRoute>
        }
      />
      <Route
        path="/login/phone"
        element={
          <PublicRoute>
            <PhoneLoginPage />
          </PublicRoute>
        }
      />
      <Route
        path="/signup"
        element={
          <PublicRoute>
            <SignupPage />
          </PublicRoute>
        }
      />
      <Route
        path="/forgot-password"
        element={
          <PublicRoute>
            <ForgotPasswordPage />
          </PublicRoute>
        }
      />

      {/* Email verification (accessible when logged in but not verified) */}
      <Route path="/verify-email" element={<VerifyEmailPage />} />

      {/* Protected routes */}
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <MainLayout>
              <DashboardPage />
            </MainLayout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/alerts"
        element={
          <ProtectedRoute>
            <MainLayout>
              <AlertsPage />
            </MainLayout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/incidents"
        element={
          <ProtectedRoute>
            <MainLayout>
              <IncidentsPage />
            </MainLayout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/events"
        element={
          <ProtectedRoute>
            <MainLayout>
              <EventsPage />
            </MainLayout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/reports"
        element={
          <ProtectedRoute>
            <MainLayout>
              <ReportsPage />
            </MainLayout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/settings"
        element={
          <ProtectedRoute>
            <MainLayout>
              <SettingsPage />
            </MainLayout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/analysis/email"
        element={
          <ProtectedRoute>
            <MainLayout>
              <EmailAnalysisPage />
            </MainLayout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/analysis/logs"
        element={
          <ProtectedRoute>
            <MainLayout>
              <LogAnalysisPage />
            </MainLayout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/analysis/network"
        element={
          <ProtectedRoute>
            <MainLayout>
              <NetworkAnalysisPage />
            </MainLayout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/agents"
        element={
          <ProtectedRoute>
            <MainLayout>
              <AgentsPage />
            </MainLayout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/correlation"
        element={
          <ProtectedRoute>
            <MainLayout>
              <CorrelationPage />
            </MainLayout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/threat-intel"
        element={
          <ProtectedRoute>
            <MainLayout>
              <ThreatIntelPage />
            </MainLayout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/feedback"
        element={
          <ProtectedRoute>
            <MainLayout>
              <FeedbackPage />
            </MainLayout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/training"
        element={
          <ProtectedRoute>
            <MainLayout>
              <TrainingPage />
            </MainLayout>
          </ProtectedRoute>
        }
      />

      {/* Catch all - redirect to dashboard */}
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}

export default App
