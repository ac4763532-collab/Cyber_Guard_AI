import { ReactNode } from "react";
import { Navigate, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "./AuthProvider";
import { Spinner } from "@/components/ui/Spinner";

interface ProtectedRouteProps {
  children?: ReactNode;
  allowedRoles?: string[];
}

export function ProtectedRoute({ children, allowedRoles }: ProtectedRouteProps) {
  const { user, isAuthenticated, isLoading } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return (
      <div className="flex h-screen items-center justify-center bg-slate-950">
        <Spinner size="lg" className="text-cyan-400" />
      </div>
    );
  }

  if (!isAuthenticated || !user) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // Role validation
  if (allowedRoles && allowedRoles.length > 0) {
    const userRole = (user.role || "individual").toLowerCase();
    const isAllowed = allowedRoles.some((r) => r.toLowerCase() === userRole || (userRole === "admin"));
    
    if (!isAllowed) {
      // Redirect to user's authorized home workspace
      if (userRole === "analyst") {
        return <Navigate to="/analyst/dashboard" replace />;
      }
      if (userRole === "organizer" || userRole === "org_admin") {
        return <Navigate to="/organization/dashboard" replace />;
      }
      return <Navigate to="/personal/dashboard" replace />;
    }
  }

  return <>{children ?? <Outlet />}</>;
}

export default ProtectedRoute;
