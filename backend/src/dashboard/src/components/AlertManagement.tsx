import React, { useEffect, useState } from 'react';
import {
  Box,
  Container,
  Paper,
  Typography,
  Button,
  TextField,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  IconButton,
  Chip,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Alert as MuiAlert,
  CircularProgress,
} from '@mui/material';
import {
  DataGrid,
  GridColDef,
  GridValueGetterParams,
  GridRenderCellParams,
} from '@mui/x-data-grid';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  PlayArrow as PlayArrowIcon,
  Stop as StopIcon,
} from '@mui/icons-material';
import { format } from 'date-fns';
import axios from 'axios';

interface AlertItem {
  id: string;
  timestamp: string;
  rule_id: string;
  rule_name: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  status: 'new' | 'in_progress' | 'resolved' | 'false_positive';
  event: any;
}

interface Rule {
  id: string;
  name: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  enabled: boolean;
  conditions: any;
  actions: any[];
}

const AlertManagement: React.FC = () => {
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [rules, setRules] = useState<Rule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [openRuleDialog, setOpenRuleDialog] = useState(false);
  const [selectedRule, setSelectedRule] = useState<Rule | null>(null);

  // Fetch alerts and rules
  useEffect(() => {
    const fetchData = async () => {
      try {
        const [alertsResponse, rulesResponse] = await Promise.all([
          axios.get<AlertItem[]>('/api/alerts'),
          axios.get<Rule[]>('/api/rules'),
        ]);
        setAlerts(alertsResponse.data);
        setRules(rulesResponse.data);
        setError(null);
      } catch (err) {
        setError('Failed to fetch data');
        console.error('Error fetching data:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 30000); // Refresh every 30 seconds

    return () => clearInterval(interval);
  }, []);

  const handleUpdateAlertStatus = async (alertId: string, newStatus: string) => {
    try {
      await axios.patch(`/api/alerts/${alertId}`, { status: newStatus });
      setAlerts((prevAlerts) =>
        prevAlerts.map((alert) =>
          alert.id === alertId
            ? { ...alert, status: newStatus as AlertItem['status'] }
            : alert
        )
      );
    } catch (err) {
      console.error('Error updating alert status:', err);
      setError('Failed to update alert status');
    }
  };

  const handleToggleRule = async (ruleId: string, enabled: boolean) => {
    try {
      await axios.patch(`/api/rules/${ruleId}`, { enabled });
      setRules((prevRules) =>
        prevRules.map((rule) =>
          rule.id === ruleId ? { ...rule, enabled } : rule
        )
      );
    } catch (err) {
      console.error('Error toggling rule:', err);
      setError('Failed to toggle rule');
    }
  };

  const handleSaveRule = async (rule: Rule) => {
    try {
      if (rule.id) {
        await axios.put(`/api/rules/${rule.id}`, rule);
        setRules((prevRules) =>
          prevRules.map((r) => (r.id === rule.id ? rule : r))
        );
      } else {
        const response = await axios.post('/api/rules', rule);
        setRules((prevRules) => [...prevRules, response.data]);
      }
      setOpenRuleDialog(false);
      setSelectedRule(null);
    } catch (err) {
      console.error('Error saving rule:', err);
      setError('Failed to save rule');
    }
  };

  const handleDeleteRule = async (ruleId: string) => {
    try {
      await axios.delete(`/api/rules/${ruleId}`);
      setRules((prevRules) => prevRules.filter((rule) => rule.id !== ruleId));
    } catch (err) {
      console.error('Error deleting rule:', err);
      setError('Failed to delete rule');
    }
  };

  const alertColumns: GridColDef[] = [
    {
      field: 'timestamp',
      headerName: 'Time',
      width: 180,
      valueGetter: (params: GridValueGetterParams) =>
        format(new Date(params.row.timestamp), 'yyyy-MM-dd HH:mm:ss'),
    },
    { field: 'rule_name', headerName: 'Rule', width: 200 },
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
    { field: 'description', headerName: 'Description', flex: 1 },
    {
      field: 'status',
      headerName: 'Status',
      width: 150,
      renderCell: (params: GridRenderCellParams) => (
        <FormControl size="small" fullWidth>
          <Select
            value={params.value}
            onChange={(e) =>
              handleUpdateAlertStatus(params.row.id, e.target.value)
            }
          >
            <MenuItem value="new">New</MenuItem>
            <MenuItem value="in_progress">In Progress</MenuItem>
            <MenuItem value="resolved">Resolved</MenuItem>
            <MenuItem value="false_positive">False Positive</MenuItem>
          </Select>
        </FormControl>
      ),
    },
  ];

  const ruleColumns: GridColDef[] = [
    { field: 'name', headerName: 'Name', width: 200 },
    { field: 'description', headerName: 'Description', flex: 1 },
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
    {
      field: 'enabled',
      headerName: 'Status',
      width: 120,
      renderCell: (params: GridRenderCellParams) => (
        <IconButton
          onClick={() => handleToggleRule(params.row.id, !params.row.enabled)}
          color={params.row.enabled ? 'success' : 'error'}
        >
          {params.row.enabled ? <PlayArrowIcon /> : <StopIcon />}
        </IconButton>
      ),
    },
    {
      field: 'actions',
      headerName: 'Actions',
      width: 120,
      renderCell: (params: GridRenderCellParams) => (
        <Box>
          <IconButton
            onClick={() => {
              setSelectedRule(params.row);
              setOpenRuleDialog(true);
            }}
          >
            <EditIcon />
          </IconButton>
          <IconButton
            onClick={() => handleDeleteRule(params.row.id)}
            color="error"
          >
            <DeleteIcon />
          </IconButton>
        </Box>
      ),
    },
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
        <MuiAlert severity="error" sx={{ mb: 2 }}>
          {error}
        </MuiAlert>
      )}

      {/* Alerts Section */}
      <Paper sx={{ mb: 4, p: 2 }}>
        <Typography variant="h6" gutterBottom>
          Active Alerts
        </Typography>
        <Box sx={{ height: 400 }}>
          <DataGrid
            rows={alerts}
            columns={alertColumns}
            initialState={{
              pagination: {
                paginationModel: { pageSize: 5, page: 0 },
              },
            }}
            pageSizeOptions={[5]}
            disableRowSelectionOnClick
          />
        </Box>
      </Paper>

      {/* Rules Section */}
      <Paper sx={{ p: 2 }}>
        <Box sx={{ mb: 2, display: 'flex', justifyContent: 'space-between' }}>
          <Typography variant="h6">Alert Rules</Typography>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => {
              setSelectedRule(null);
              setOpenRuleDialog(true);
            }}
          >
            Add Rule
          </Button>
        </Box>
        <Box sx={{ height: 400 }}>
          <DataGrid
            rows={rules}
            columns={ruleColumns}
            initialState={{
              pagination: {
                paginationModel: { pageSize: 5, page: 0 },
              },
            }}
            pageSizeOptions={[5]}
            disableRowSelectionOnClick
          />
        </Box>
      </Paper>

      {/* Rule Dialog */}
      <Dialog
        open={openRuleDialog}
        onClose={() => {
          setOpenRuleDialog(false);
          setSelectedRule(null);
        }}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          {selectedRule ? 'Edit Rule' : 'Create New Rule'}
        </DialogTitle>
        <DialogContent>
          <Box sx={{ mt: 2 }}>
            <TextField
              label="Name"
              fullWidth
              value={selectedRule?.name || ''}
              onChange={(e) =>
                setSelectedRule((prev) =>
                  prev ? { ...prev, name: e.target.value } : null
                )
              }
              sx={{ mb: 2 }}
            />
            <TextField
              label="Description"
              fullWidth
              multiline
              rows={3}
              value={selectedRule?.description || ''}
              onChange={(e) =>
                setSelectedRule((prev) =>
                  prev ? { ...prev, description: e.target.value } : null
                )
              }
              sx={{ mb: 2 }}
            />
            <FormControl fullWidth sx={{ mb: 2 }}>
              <InputLabel>Severity</InputLabel>
              <Select
                value={selectedRule?.severity || 'low'}
                onChange={(e) =>
                  setSelectedRule((prev) =>
                    prev
                      ? {
                          ...prev,
                          severity: e.target.value as Rule['severity'],
                        }
                      : null
                  )
                }
              >
                <MenuItem value="critical">Critical</MenuItem>
                <MenuItem value="high">High</MenuItem>
                <MenuItem value="medium">Medium</MenuItem>
                <MenuItem value="low">Low</MenuItem>
              </Select>
            </FormControl>
            <TextField
              label="Conditions"
              fullWidth
              multiline
              rows={4}
              value={
                selectedRule?.conditions
                  ? JSON.stringify(selectedRule.conditions, null, 2)
                  : ''
              }
              onChange={(e) =>
                setSelectedRule((prev) =>
                  prev
                    ? {
                        ...prev,
                        conditions: JSON.parse(e.target.value),
                      }
                    : null
                )
              }
              sx={{ mb: 2 }}
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => {
              setOpenRuleDialog(false);
              setSelectedRule(null);
            }}
          >
            Cancel
          </Button>
          <Button
            onClick={() => selectedRule && handleSaveRule(selectedRule)}
            variant="contained"
          >
            Save
          </Button>
        </DialogActions>
      </Dialog>
    </Container>
  );
};

export default AlertManagement;
