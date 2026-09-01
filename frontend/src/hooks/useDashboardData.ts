import { useState, useEffect } from 'react';
import AuthService from '@/services/authService';

interface DashboardData {
  summary: any;
  alerts: any[];
  loading: boolean;
  error: string | null;
}

export function useDashboardData() {
  const [dashboardData, setDashboardData] = useState<DashboardData>({
    summary: null,
    alerts: [],
    loading: true,
    error: null
  });

  useEffect(() => {
    async function fetchDashboardData() {
      try {
        // Reset loading and error states
        setDashboardData(prev => ({
          ...prev, 
          loading: true, 
          error: null
        }));

        // Get authentication headers
        const headers = AuthService.getAuthHeader();

        console.group('Dashboard Data Fetch');
        console.log('Authentication Headers:', headers);

        // Fetch dashboard summary
        const summaryResponse = await fetch('http://localhost:8000/dashboard/summary', {
          method: 'GET',
          headers: {
            'Accept': 'application/json',
            ...headers
          }
        });

        console.log('Summary Response Status:', summaryResponse.status);

        if (!summaryResponse.ok) {
          const errorText = await summaryResponse.text();
          console.error('Dashboard fetch error:', errorText);
          
          throw new Error(errorText || 'Failed to fetch dashboard summary');
        }

        const summaryData = await summaryResponse.json();
        console.log('Summary Data:', summaryData);
        console.groupEnd();

        // Fetch alerts (similar pattern)
        const alertsResponse = await fetch('http://localhost:8000/dashboard/alerts', {
          method: 'GET',
          headers: {
            'Accept': 'application/json',
            ...headers
          }
        });

        const alertsData = await alertsResponse.json();

        setDashboardData({
          summary: summaryData,
          alerts: alertsData,
          loading: false,
          error: null
        });

      } catch (error: any) {
        console.group('Dashboard Fetch Error');
        console.error('Full error:', error);
        console.log('Error message:', error.message);
        console.log('Error name:', error.name);
        console.groupEnd();

        setDashboardData({
          summary: null,
          alerts: [],
          loading: false,
          error: error.message || 'An unexpected error occurred'
        });

        // Optional: Redirect to login if unauthorized
        if (error.message.includes('401')) {
          AuthService.logout();
          window.location.href = '/login';
        }
      }
    }

    // Only fetch if authenticated
    if (AuthService.isAuthenticated()) {
      fetchDashboardData();
    }
  }, []); // Consider adding dependencies if needed

  return dashboardData;
}
