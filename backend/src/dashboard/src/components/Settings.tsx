import React, { useEffect, useState } from 'react';
import {
  Box,
  Container,
  Paper,
  Typography,
  TextField,
  Button,
  Grid,
  Switch,
  FormControlLabel,
  Alert,
  CircularProgress,
  Snackbar,
} from '@mui/material';
import { Save as SaveIcon } from '@mui/icons-material';
import axios from 'axios';

interface SystemSettings {
  retention_days: number;
  max_events_per_minute: number;
  enable_ml_detection: boolean;
  enable_automated_response: boolean;
  alert_email: string;
  api_endpoint: string;
  log_level: string;
  backup_enabled: boolean;
  backup_frequency_hours: number;
  backup_location: string;
}

const Settings: React.FC = () => {
  const [settings, setSettings] = useState<SystemSettings>({
    retention_days: 30,
    max_events_per_minute: 1000,
    enable_ml_detection: true,
    enable_automated_response: false,
    alert_email: '',
    api_endpoint: '',
    log_level: 'info',
    backup_enabled: true,
    backup_frequency_hours: 24,
    backup_location: '',
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  useEffect(() => {
    const fetchSettings = async () => {
      try {
        const response = await axios.get<SystemSettings>('/api/settings');
        setSettings(response.data);
        setError(null);
      } catch (err) {
        setError('Failed to fetch system settings');
        console.error('Error fetching settings:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchSettings();
  }, []);

  const handleSaveSettings = async () => {
    try {
      await axios.put('/api/settings', settings);
      setSuccessMessage('Settings saved successfully');
      setError(null);
    } catch (err) {
      setError('Failed to save settings');
      console.error('Error saving settings:', err);
    }
  };

  const handleChange = (field: keyof SystemSettings) => (
    event: React.ChangeEvent<HTMLInputElement>
  ) => {
    const value =
      event.target.type === 'checkbox'
        ? event.target.checked
        : event.target.type === 'number'
        ? Number(event.target.value)
        : event.target.value;
    setSettings((prev) => ({ ...prev, [field]: value }));
  };

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

      <Snackbar
        open={!!successMessage}
        autoHideDuration={6000}
        onClose={() => setSuccessMessage(null)}
        message={successMessage}
      />

      {/* General Settings */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          General Settings
        </Typography>
        <Grid container spacing={3}>
          <Grid item xs={12} sm={6}>
            <TextField
              label="Event Retention (days)"
              type="number"
              fullWidth
              value={settings.retention_days}
              onChange={handleChange('retention_days')}
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              label="Max Events per Minute"
              type="number"
              fullWidth
              value={settings.max_events_per_minute}
              onChange={handleChange('max_events_per_minute')}
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              label="Alert Email"
              type="email"
              fullWidth
              value={settings.alert_email}
              onChange={handleChange('alert_email')}
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              label="API Endpoint"
              fullWidth
              value={settings.api_endpoint}
              onChange={handleChange('api_endpoint')}
            />
          </Grid>
        </Grid>
      </Paper>

      {/* Feature Toggles */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          Feature Settings
        </Typography>
        <Grid container spacing={3}>
          <Grid item xs={12} sm={6}>
            <FormControlLabel
              control={
                <Switch
                  checked={settings.enable_ml_detection}
                  onChange={handleChange('enable_ml_detection')}
                />
              }
              label="Enable ML-based Threat Detection"
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <FormControlLabel
              control={
                <Switch
                  checked={settings.enable_automated_response}
                  onChange={handleChange('enable_automated_response')}
                />
              }
              label="Enable Automated Response"
            />
          </Grid>
        </Grid>
      </Paper>

      {/* Backup Settings */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          Backup Settings
        </Typography>
        <Grid container spacing={3}>
          <Grid item xs={12} sm={6}>
            <FormControlLabel
              control={
                <Switch
                  checked={settings.backup_enabled}
                  onChange={handleChange('backup_enabled')}
                />
              }
              label="Enable Automated Backups"
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              label="Backup Frequency (hours)"
              type="number"
              fullWidth
              value={settings.backup_frequency_hours}
              onChange={handleChange('backup_frequency_hours')}
              disabled={!settings.backup_enabled}
            />
          </Grid>
          <Grid item xs={12}>
            <TextField
              label="Backup Location"
              fullWidth
              value={settings.backup_location}
              onChange={handleChange('backup_location')}
              disabled={!settings.backup_enabled}
            />
          </Grid>
        </Grid>
      </Paper>

      {/* Save Button */}
      <Box display="flex" justifyContent="flex-end">
        <Button
          variant="contained"
          color="primary"
          startIcon={<SaveIcon />}
          onClick={handleSaveSettings}
        >
          Save Settings
        </Button>
      </Box>
    </Container>
  );
};

export default Settings;
