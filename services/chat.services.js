// services/chart.service.js
// Server-side chart generation service
//
// Generates PNG charts using Chart.js (via chartjs-node-canvas)
// Used by report.workflow.js to build PDF reports

const { ChartJSNodeCanvas } = require("chartjs-node-canvas");
const path = require("path");
const fs = require("fs");

// -------------------------------
// Chart canvas setup
// -------------------------------
const WIDTH = 800;
const HEIGHT = 400;
const BACKGROUND_COLOR = "white";

const chartJSNodeCanvas = new ChartJSNodeCanvas({
  width: WIDTH,
  height: HEIGHT,
  backgroundColour: BACKGROUND_COLOR
});

// -------------------------------
// Helpers
// -------------------------------
function ensureDir(dirPath) {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }
}

function saveChart(buffer, filePath) {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, buffer);
  return filePath;
}

function defaultColors(count = 5) {
  const base = [
    "#4F46E5", // indigo
    "#22C55E", // green
    "#F59E0B", // amber
    "#EF4444", // red
    "#0EA5E9", // sky
    "#A855F7"  // purple
  ];
  return Array.from({ length: count }, (_, i) => base[i % base.length]);
}

// -------------------------------
// Chart generators
// -------------------------------

async function generatePieChart({
  labels,
  data,
  title,
  outputPath
}) {
  const config = {
    type: "pie",
    data: {
      labels,
      datasets: [
        {
          data,
          backgroundColor: defaultColors(data.length)
        }
      ]
    },
    options: {
      plugins: {
        title: {
          display: true,
          text: title,
          font: { size: 18 }
        },
        legend: {
          position: "bottom"
        }
      }
    }
  };

  const buffer = await chartJSNodeCanvas.renderToBuffer(config);
  return saveChart(buffer, outputPath);
}

async function generateBarChart({
  labels,
  data,
  title,
  outputPath,
  horizontal = false
}) {
  const config = {
    type: "bar",
    data: {
      labels,
      datasets: [
        {
          label: title,
          data,
          backgroundColor: defaultColors(data.length)
        }
      ]
    },
    options: {
      indexAxis: horizontal ? "y" : "x",
      plugins: {
        title: {
          display: true,
          text: title,
          font: { size: 18 }
        },
        legend: {
          display: false
        }
      },
      scales: {
        x: {
          beginAtZero: true
        },
        y: {
          beginAtZero: true
        }
      }
    }
  };

  const buffer = await chartJSNodeCanvas.renderToBuffer(config);
  return saveChart(buffer, outputPath);
}

async function generateLineChart({
  labels,
  data,
  title,
  outputPath
}) {
  const config = {
    type: "line",
    data: {
      labels,
      datasets: [
        {
          label: title,
          data,
          fill: false,
          borderColor: "#4F46E5",
          tension: 0.3
        }
      ]
    },
    options: {
      plugins: {
        title: {
          display: true,
          text: title,
          font: { size: 18 }
        },
        legend: {
          display: false
        }
      },
      scales: {
        x: {
          title: {
            display: true,
            text: "Time"
          }
        },
        y: {
          beginAtZero: true
        }
      }
    }
  };

  const buffer = await chartJSNodeCanvas.renderToBuffer(config);
  return saveChart(buffer, outputPath);
}

// -------------------------------
// High-level report charts
// -------------------------------

async function buildReportCharts({
  analytics,
  outputDir
}) {
  ensureDir(outputDir);

  const files = {};

  // 1️⃣ AI vs Escalated (Pie)
  files.aiVsEscalation = await generatePieChart({
    labels: ["AI Handled", "Escalated to Owner"],
    data: [
      analytics.summary.aiHandled,
      analytics.summary.escalated
    ],
    title: "AI Resolution vs Owner Involvement",
    outputPath: path.join(outputDir, "ai_vs_escalation.png")
  });

  // 2️⃣ Channel distribution (Bar)
  const channelLabels = Object.keys(analytics.channels);
  const channelData = Object.values(analytics.channels);

  files.channels = await generateBarChart({
    labels: channelLabels,
    data: channelData,
    title: "Customer Conversations by Channel",
    outputPath: path.join(outputDir, "channels.png")
  });

  // 3️⃣ Top intents (Bar horizontal)
  const intentLabels = analytics.topIntents.map(i => i.intent);
  const intentData = analytics.topIntents.map(i => i.count);

  files.intents = await generateBarChart({
    labels: intentLabels,
    data: intentData,
    title: "Top Customer Issues",
    outputPath: path.join(outputDir, "top_intents.png"),
    horizontal: true
  });

  // 4️⃣ Peak hours (Line)
  const hourLabels = analytics.peakHours.map(h => `${h.hour}:00`);
  const hourData = analytics.peakHours.map(h => h.count);

  files.peakHours = await generateLineChart({
    labels: hourLabels,
    data: hourData,
    title: "Customer Activity by Hour",
    outputPath: path.join(outputDir, "peak_hours.png")
  });

  return files;
}

// -------------------------------
// Exports
// -------------------------------
module.exports = {
  generatePieChart,
  generateBarChart,
  generateLineChart,
  buildReportCharts
};
