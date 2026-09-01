"use client";

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import AuthService from '@/services/authService';

export function withAuth<P extends object>(
  WrappedComponent: React.ComponentType<P>
) {
  return function AuthWrapper(props: P) {
    const router = useRouter();

    useEffect(() => {
      const token = AuthService.getToken();
      if (!token) {
        router.replace('/login');
      }
    }, [router]);

    return <WrappedComponent {...props} />;
  };
}

export function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const router = useRouter();

  useEffect(() => {
    const token = AuthService.getToken();
    if (!token) {
      router.replace('/login');
    }
  }, [router]);

  return <>{children}</>;
}
