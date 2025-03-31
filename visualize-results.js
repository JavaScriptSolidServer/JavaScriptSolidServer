import fs from 'fs/promises';
import path from 'path';

/**
 * Simple script to generate an HTML report with charts from benchmark results
 * Usage: node visualize-results.js path/to/benchmark-report.json
 */

async function generateVisualization () {
  // Get the report file path from command line args
  const reportPath = process.argv[2];

  if (!reportPath) {
    console.error('Please provide a path to the benchmark report JSON file.');
    console.error('Usage: node visualize-results.js path/to/benchmark-report.json');
    process.exit(1);
  }

  try {
    // Read and parse the report file
    const reportContent = await fs.readFile(reportPath, 'utf8');
    const report = JSON.parse(reportContent);

    // Create the HTML template with embedded Chart.js
    const htmlContent = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JavaScriptSolid Server Benchmark Results</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
            margin: 0;
            padding: 20px;
            color: #333;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1, h2 {
            color: #2c3e50;
        }
        .chart-container {
            margin: 30px 0;
            height: 400px;
        }
        .metrics {
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            margin: 20px 0;
        }
        .metric-card {
            background-color: #f8f9fa;
            border-radius: 6px;
            padding: 15px;
            width: 18%;
            margin-bottom: 15px;
            box-shadow: 0 1px 5px rgba(0,0,0,0.05);
        }
        .metric-card h3 {
            margin: 0 0 10px 0;
            color: #2c3e50;
        }
        .metric-value {
            font-size: 24px;
            font-weight: bold;
            color: #3498db;
        }
        .info {
            background-color: #e8f4fd;
            padding: 15px;
            border-radius: 6px;
            margin: 20px 0;
            border-left: 4px solid #3498db;
        }
        @media (max-width: 768px) {
            .metric-card {
                width: 45%;
            }
        }
        @media (max-width: 480px) {
            .metric-card {
                width: 100%;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>JavaScriptSolid Server Benchmark Results</h1>
        <div class="info">
            <strong>Server:</strong> ${report.server}<br>
            <strong>Test Date:</strong> ${new Date(report.timestamp).toLocaleString()}<br>
            <strong>Test Duration:</strong> ${report.testDuration / 1000} seconds per concurrency level
        </div>
        
        <h2>Response Time Metrics</h2>
        <div class="metrics">
            <div class="metric-card">
                <h3>Register</h3>
                <div class="metric-value">${report.averageResponseTimes.register.toFixed(2)} ms</div>
            </div>
            <div class="metric-card">
                <h3>Login</h3>
                <div class="metric-value">${report.averageResponseTimes.login.toFixed(2)} ms</div>
            </div>
            <div class="metric-card">
                <h3>Read</h3>
                <div class="metric-value">${report.averageResponseTimes.read.toFixed(2)} ms</div>
            </div>
            <div class="metric-card">
                <h3>Write</h3>
                <div class="metric-value">${report.averageResponseTimes.write.toFixed(2)} ms</div>
            </div>
            <div class="metric-card">
                <h3>Delete</h3>
                <div class="metric-value">${report.averageResponseTimes.delete.toFixed(2)} ms</div>
            </div>
        </div>
        
        <h2>Response Time Comparison</h2>
        <div class="chart-container">
            <canvas id="responseTimeChart"></canvas>
        </div>
        
        <h2>Throughput by Concurrent Users</h2>
        <div class="chart-container">
            <canvas id="throughputChart"></canvas>
        </div>
    </div>
    
    <script>
        // Data from the benchmark report
        const responseTimeData = {
            labels: ['Register', 'Login', 'Read', 'Write', 'Delete'],
            datasets: [{
                label: 'Average Response Time (ms)',
                data: [
                    ${report.averageResponseTimes.register.toFixed(2)},
                    ${report.averageResponseTimes.login.toFixed(2)},
                    ${report.averageResponseTimes.read.toFixed(2)},
                    ${report.averageResponseTimes.write.toFixed(2)},
                    ${report.averageResponseTimes.delete.toFixed(2)}
                ],
                backgroundColor: [
                    'rgba(52, 152, 219, 0.5)',
                    'rgba(46, 204, 113, 0.5)',
                    'rgba(155, 89, 182, 0.5)',
                    'rgba(230, 126, 34, 0.5)',
                    'rgba(231, 76, 60, 0.5)'
                ],
                borderColor: [
                    'rgba(52, 152, 219, 1)',
                    'rgba(46, 204, 113, 1)',
                    'rgba(155, 89, 182, 1)',
                    'rgba(230, 126, 34, 1)',
                    'rgba(231, 76, 60, 1)'
                ],
                borderWidth: 1
            }]
        };
        
        // Throughput data from the report
        const throughputData = {
            labels: ${JSON.stringify(report.throughputResults.map(r => r.concurrentUsers + ' Users'))},
            datasets: [{
                label: 'Operations per Second',
                data: ${JSON.stringify(report.throughputResults.map(r => r.throughput.toFixed(2)))},
                backgroundColor: 'rgba(52, 152, 219, 0.5)',
                borderColor: 'rgba(52, 152, 219, 1)',
                borderWidth: 1
            }]
        };
        
        // Create the charts
        window.onload = function() {
            // Response time chart
            const rtCtx = document.getElementById('responseTimeChart').getContext('2d');
            new Chart(rtCtx, {
                type: 'bar',
                data: responseTimeData,
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        title: {
                            display: true,
                            text: 'Average Response Time by Operation Type'
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: 'Time (ms)'
                            }
                        }
                    }
                }
            });
            
            // Throughput chart
            const tpCtx = document.getElementById('throughputChart').getContext('2d');
            new Chart(tpCtx, {
                type: 'line',
                data: throughputData,
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        title: {
                            display: true,
                            text: 'Throughput by Concurrent Users'
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: 'Operations per Second'
                            }
                        }
                    }
                }
            });
        };
    </script>
</body>
</html>
    `;

    // Write the HTML file
    const htmlFilePath = `benchmark-report-${path.basename(reportPath, '.json')}.html`;
    await fs.writeFile(htmlFilePath, htmlContent);

    console.log(`Visualization generated successfully: ${htmlFilePath}`);
    console.log(`Open this file in a web browser to view the charts.`);

  } catch (error) {
    console.error('Error generating visualization:', error.message);
    process.exit(1);
  }
}

// Run the visualization generator
generateVisualization(); 