const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const winston = require('winston');
const path = require('path');

// Initialize Express app
const app = express();
const port = process.env.PORT || 3000;

// Configure logging
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
        new winston.transports.File({ filename: 'logs/combined.log' })
    ]
});

// Middleware
app.use(helmet()); // Security headers
app.use(cors());   // Enable CORS
app.use(compression()); // Compress responses
app.use(express.json()); // Parse JSON bodies
app.use(morgan('combined')); // HTTP request logging

// Basic routes
app.get('/api/health', (req, res) => {
    res.json({ status: 'healthy', timestamp: new Date() });
});

// ML Threat Detection endpoint
app.post('/api/threat-detection', (req, res) => {
    try {
        // This will be integrated with the ML detection module
        res.json({
            status: 'success',
            message: 'Threat detection analysis completed',
            timestamp: new Date()
        });
    } catch (error) {
        logger.error('Error in threat detection:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    logger.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
app.listen(port, () => {
    logger.info(`SIEM server listening on port ${port}`);
    console.log(`SIEM server listening on port ${port}`);
});
