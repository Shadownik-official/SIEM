import React, { useEffect, useState } from 'react';
import {
  Box,
  Container,
  Grid,
  Paper,
  Typography,
  useTheme,
  CircularProgress,
  Alert,
} from '@mui/material';
import {
  Timeline,
  Security,
  Warning,
  Error as ErrorIcon,
} from '@mui/icons-material';
import { Line, Pie } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
} from 'chart.js';
import { format } from 'date-fns';
import axios from 'axios';

// Register ChartJS components
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  ArcElement
);

interface DashboardStats {
  totalEvents: number;
  totalAlerts: number;
  severityCounts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  eventsBySource: {
    [key: string]: number;
  };
  recentEvents: Array<{
    timestamp: string;
    source: string;
    type: string;
    severity: string;
  }>;
}

const Dashboard: React.FC = () => {
  const theme = useTheme();
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const response = await axios.get<DashboardStats>('/api/dashboard/stats');
        setStats(response.data);
        setError(null);
      } catch (err) {
        setError('Failed to fetch dashboard statistics');
        console.error('Error fetching stats:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchStats();
    const interval = setInterval(fetchStats, 30000); // Refresh every 30 seconds

    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <Box
        display="flex"
        justifyContent="center"
        alignItems="center"
        minHeight="100vh"
      >
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Box m={2}>
        <Alert severity="error">{error}</Alert>
      </Box>
    );
  }

  if (!stats) {
    return null;
  }

  // Prepare chart data
  const severityChartData = {
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [
      {
        data: [
          stats.severityCounts.critical,
          stats.severityCounts.high,
          stats.severityCounts.medium,
          stats.severityCounts.low,
        ],
        backgroundColor: [
          theme.palette.error.main,
          theme.palette.warning.main,
          theme.palette.info.main,
          theme.palette.success.main,
        ],
      },
    ],
  };

  const eventTimelineData = {
    labels: stats.recentEvents.map((event) =>
      format(new Date(event.timestamp), 'HH:mm:ss')
    ),
    datasets: [
      {
        label: 'Events',
        data: stats.recentEvents.map((_, index) => index + 1),
        borderColor: theme.palette.primary.main,
        tension: 0.4,
      },
    ],
  };

  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      <Grid container spacing={3}>
        {/* Summary Cards */}
        <Grid item xs={12} sm={6} md={3}>
          <Paper
            sx={{
              p: 2,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
            }}
          >
            <Timeline color="primary" sx={{ fontSize: 40, mb: 1 }} />
            <Typography variant="h6">Total Events</Typography>
            <Typography variant="h4">{stats.totalEvents}</Typography>
          </Paper>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Paper
            sx={{
              p: 2,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
            }}
          >
            <Warning color="warning" sx={{ fontSize: 40, mb: 1 }} />
            <Typography variant="h6">Total Alerts</Typography>
            <Typography variant="h4">{stats.totalAlerts}</Typography>
          </Paper>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Paper
            sx={{
              p: 2,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
            }}
          >
            <ErrorIcon color="error" sx={{ fontSize: 40, mb: 1 }} />
            <Typography variant="h6">Critical Events</Typography>
            <Typography variant="h4">{stats.severityCounts.critical}</Typography>
          </Paper>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Paper
            sx={{
              p: 2,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
            }}
          >
            <Security color="success" sx={{ fontSize: 40, mb: 1 }} />
            <Typography variant="h6">System Status</Typography>
            <Typography variant="h4" color="success.main">
              Active
            </Typography>
          </Paper>
        </Grid>

        {/* Charts */}
        <Grid item xs={12} md={8}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              Event Timeline
            </Typography>
            <Box sx={{ height: 300 }}>
              <Line
                data={eventTimelineData}
                options={{
                  responsive: true,
                  maintainAspectRatio: false,
                  scales: {
                    y: {
                      beginAtZero: true,
                    },
                  },
                }}
              />
            </Box>
          </Paper>
        </Grid>
        <Grid item xs={12} md={4}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              Event Severity Distribution
            </Typography>
            <Box sx={{ height: 300 }}>
              <Pie
                data={severityChartData}
                options={{
                  responsive: true,
                  maintainAspectRatio: false,
                }}
              />
            </Box>
          </Paper>
        </Grid>

        {/* Recent Events Table */}
        <Grid item xs={12}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              Recent Events
            </Typography>
            <Box sx={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Source</th>
                    <th>Type</th>
                    <th>Severity</th>
                  </tr>
                </thead>
                <tbody>
                  {stats.recentEvents.map((event, index) => (
                    <tr key={index}>
                      <td>{format(new Date(event.timestamp), 'HH:mm:ss')}</td>
                      <td>{event.source}</td>
                      <td>{event.type}</td>
                      <td>
                        <Box
                          component="span"
                          sx={{
                            color: theme.palette[
                              event.severity === 'critical'
                                ? 'error'
                                : event.severity === 'high'
                                ? 'warning'
                                : event.severity === 'medium'
                                ? 'info'
                                : 'success'
                            ].main,
                            fontWeight: 'bold',
                          }}
                        >
                          {event.severity.toUpperCase()}
                        </Box>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Box>
          </Paper>
        </Grid>
      </Grid>
    </Container>
  );
};

export default Dashboard;
