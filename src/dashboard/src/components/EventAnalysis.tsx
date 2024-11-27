import React, { useEffect, useState } from 'react';
import {
  Box,
  Container,
  Paper,
  Typography,
  TextField,
  Button,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Grid,
  Chip,
  Alert,
  CircularProgress,
} from '@mui/material';
import {
  DataGrid,
  GridColDef,
  GridValueGetterParams,
  GridRenderCellParams,
} from '@mui/x-data-grid';
import { Search as SearchIcon } from '@mui/icons-material';
import { format } from 'date-fns';
import axios from 'axios';

interface Event {
  id: string;
  timestamp: string;
  source: string;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  message: string;
  metadata: Record<string, any>;
}

interface EventStats {
  totalEvents: number;
  eventsBySource: Record<string, number>;
  eventsByType: Record<string, number>;
  eventsBySeverity: Record<string, number>;
  timelineData: Array<{
    timestamp: string;
    count: number;
  }>;
}

const EventAnalysis: React.FC = () => {
  const [events, setEvents] = useState<Event[]>([]);
  const [stats, setStats] = useState<EventStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filters, setFilters] = useState({
    source: '',
    type: '',
    severity: '',
    startDate: format(new Date(Date.now() - 24 * 60 * 60 * 1000), 'yyyy-MM-dd'),
    endDate: format(new Date(), 'yyyy-MM-dd'),
    searchQuery: '',
  });

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [eventsResponse, statsResponse] = await Promise.all([
          axios.get<Event[]>('/api/events', { params: filters }),
          axios.get<EventStats>('/api/events/stats', { params: filters }),
        ]);
        setEvents(eventsResponse.data);
        setStats(statsResponse.data);
        setError(null);
      } catch (err) {
        setError('Failed to fetch event data');
        console.error('Error fetching event data:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [filters]);

  const handleSearch = () => {
    setLoading(true);
    // The useEffect will trigger a new data fetch
  };

  const columns: GridColDef[] = [
    {
      field: 'timestamp',
      headerName: 'Time',
      width: 180,
      valueGetter: (params: GridValueGetterParams) =>
        format(new Date(params.row.timestamp), 'yyyy-MM-dd HH:mm:ss'),
    },
    { field: 'source', headerName: 'Source', width: 150 },
    { field: 'type', headerName: 'Type', width: 150 },
    {
      field: 'severity',
      headerName: 'Severity',
      width: 120,
      renderCell: (params: GridRenderCellParams) => (
        <Chip
          label={params.value.toUpperCase()}
          color={
            params.value === 'critical'
              ? 'error'
              : params.value === 'high'
              ? 'warning'
              : params.value === 'medium'
              ? 'info'
              : 'success'
          }
          size="small"
        />
      ),
    },
    { field: 'message', headerName: 'Message', flex: 1 },
  ];

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

  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      {/* Filters */}
      <Paper sx={{ p: 2, mb: 4 }}>
        <Typography variant="h6" gutterBottom>
          Event Filters
        </Typography>
        <Grid container spacing={2}>
          <Grid item xs={12} sm={6} md={3}>
            <TextField
              label="Start Date"
              type="date"
              fullWidth
              value={filters.startDate}
              onChange={(e) =>
                setFilters((prev) => ({ ...prev, startDate: e.target.value }))
              }
              InputLabelProps={{ shrink: true }}
            />
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <TextField
              label="End Date"
              type="date"
              fullWidth
              value={filters.endDate}
              onChange={(e) =>
                setFilters((prev) => ({ ...prev, endDate: e.target.value }))
              }
              InputLabelProps={{ shrink: true }}
            />
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <FormControl fullWidth>
              <InputLabel>Source</InputLabel>
              <Select
                value={filters.source}
                onChange={(e) =>
                  setFilters((prev) => ({ ...prev, source: e.target.value }))
                }
              >
                <MenuItem value="">All</MenuItem>
                {stats &&
                  Object.keys(stats.eventsBySource).map((source) => (
                    <MenuItem key={source} value={source}>
                      {source}
                    </MenuItem>
                  ))}
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <FormControl fullWidth>
              <InputLabel>Type</InputLabel>
              <Select
                value={filters.type}
                onChange={(e) =>
                  setFilters((prev) => ({ ...prev, type: e.target.value }))
                }
              >
                <MenuItem value="">All</MenuItem>
                {stats &&
                  Object.keys(stats.eventsByType).map((type) => (
                    <MenuItem key={type} value={type}>
                      {type}
                    </MenuItem>
                  ))}
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <FormControl fullWidth>
              <InputLabel>Severity</InputLabel>
              <Select
                value={filters.severity}
                onChange={(e) =>
                  setFilters((prev) => ({ ...prev, severity: e.target.value }))
                }
              >
                <MenuItem value="">All</MenuItem>
                <MenuItem value="critical">Critical</MenuItem>
                <MenuItem value="high">High</MenuItem>
                <MenuItem value="medium">Medium</MenuItem>
                <MenuItem value="low">Low</MenuItem>
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={12} sm={6} md={7}>
            <TextField
              label="Search Query"
              fullWidth
              value={filters.searchQuery}
              onChange={(e) =>
                setFilters((prev) => ({ ...prev, searchQuery: e.target.value }))
              }
              placeholder="Search in event messages..."
            />
          </Grid>
          <Grid
            item
            xs={12}
            sm={6}
            md={2}
            sx={{ display: 'flex', alignItems: 'center' }}
          >
            <Button
              variant="contained"
              fullWidth
              startIcon={<SearchIcon />}
              onClick={handleSearch}
            >
              Search
            </Button>
          </Grid>
        </Grid>
      </Paper>

      {/* Statistics */}
      <Paper sx={{ p: 2, mb: 4 }}>
        <Typography variant="h6" gutterBottom>
          Event Statistics
        </Typography>
        <Grid container spacing={2}>
          <Grid item xs={12} sm={6} md={3}>
            <Paper
              elevation={0}
              sx={{ p: 2, textAlign: 'center', bgcolor: 'grey.100' }}
            >
              <Typography variant="subtitle1">Total Events</Typography>
              <Typography variant="h4">{stats?.totalEvents || 0}</Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Paper
              elevation={0}
              sx={{ p: 2, textAlign: 'center', bgcolor: 'grey.100' }}
            >
              <Typography variant="subtitle1">Unique Sources</Typography>
              <Typography variant="h4">
                {stats ? Object.keys(stats.eventsBySource).length : 0}
              </Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Paper
              elevation={0}
              sx={{ p: 2, textAlign: 'center', bgcolor: 'grey.100' }}
            >
              <Typography variant="subtitle1">Event Types</Typography>
              <Typography variant="h4">
                {stats ? Object.keys(stats.eventsByType).length : 0}
              </Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Paper
              elevation={0}
              sx={{ p: 2, textAlign: 'center', bgcolor: 'error.light' }}
            >
              <Typography variant="subtitle1" sx={{ color: 'white' }}>
                Critical Events
              </Typography>
              <Typography variant="h4" sx={{ color: 'white' }}>
                {stats?.eventsBySeverity['critical'] || 0}
              </Typography>
            </Paper>
          </Grid>
        </Grid>
      </Paper>

      {/* Events Table */}
      <Paper sx={{ p: 2 }}>
        <Typography variant="h6" gutterBottom>
          Event Log
        </Typography>
        <Box sx={{ height: 600 }}>
          <DataGrid
            rows={events}
            columns={columns}
            initialState={{
              pagination: {
                paginationModel: { pageSize: 10, page: 0 },
              },
            }}
            pageSizeOptions={[10]}
            disableRowSelectionOnClick
            density="compact"
          />
        </Box>
      </Paper>
    </Container>
  );
};

export default EventAnalysis;
