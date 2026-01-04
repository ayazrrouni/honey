let sessionsChart, commandsChart, severityChart;

/* ===============================
   INIT CHARTS
================================ */
function initCharts(data) {
  const labels = Object.keys(data);

  sessionsChart = new Chart(
    document.getElementById("sessionsChart"),
    {
      type: "line",
      data: {
        labels,
        datasets: [{
          label: "Sessions",
          data: labels.map(k => data[k].sessions),
          borderColor: "#38bdf8",
          backgroundColor: "rgba(56,189,248,0.3)",
          borderWidth: 3,
          fill: true,
          tension: 0.4
        }]
      },
      options: { responsive:true, maintainAspectRatio:false }
    }
  );

  commandsChart = new Chart(
    document.getElementById("commandsChart"),
    {
      type: "line",
      data: {
        labels,
        datasets: [{
          label: "Commands",
          data: labels.map(k => data[k].commands),
          borderColor: "#22c55e",
          backgroundColor: "rgba(34,197,94,0.3)",
          borderWidth: 3,
          fill: true,
          tension: 0.4
        }]
      },
      options: { responsive:true, maintainAspectRatio:false }
    }
  );

  severityChart = new Chart(
    document.getElementById("severityChart"),
    {
      type: "doughnut",
      data: {
        labels: ["High", "Medium", "Low"],
        datasets: [{
          data: [
            labels.reduce((a,k)=>a+data[k].high,0),
            labels.reduce((a,k)=>a+data[k].medium,0),
            labels.reduce((a,k)=>a+data[k].low,0)
          ],
          backgroundColor: ["#22c55e", "#38bdf8", "#2dd4bf"]
        }]
      },
      options: { responsive:true, maintainAspectRatio:false }
    }
  );
}

/* ===============================
   UPDATE NUMBERS (FIXED)
================================ */
function updateNumbers(data) {
  document.querySelectorAll(".chart-container[data-service]").forEach(card => {
    const svc = card.dataset.service;
    const value = card.querySelector(".session-count");
    const circle = card.querySelector(".percentage");

    if (!data[svc]) return;

    if (value) {
      value.textContent = data[svc].sessions;
    }

    if (circle) {
      circle.textContent = data[svc].commands;
    }
  });
}

/* ===============================
   UPDATE CHARTS
================================ */
function updateCharts(data) {
  const labels = Object.keys(data);

  sessionsChart.data.datasets[0].data =
    labels.map(k => data[k].sessions);

  commandsChart.data.datasets[0].data =
    labels.map(k => data[k].commands);

  severityChart.data.datasets[0].data = [
    labels.reduce((a,k)=>a+data[k].high,0),
    labels.reduce((a,k)=>a+data[k].medium,0),
    labels.reduce((a,k)=>a+data[k].low,0)
  ];

  sessionsChart.update();
  commandsChart.update();
  severityChart.update();
}

/* ===============================
   FETCH LOOP
================================ */
function fetchStats() {
  fetch("/api/stats")
    .then(r => r.json())
    .then(data => {
      updateNumbers(data);
      updateCharts(data);
    })
    .catch(err => console.error("Fetch error:", err));
}

/* ===============================
   START
================================ */
document.addEventListener("DOMContentLoaded", () => {
  fetch("/api/stats")
    .then(r => r.json())
    .then(data => {
      initCharts(data);
      setInterval(fetchStats, 5000); // كل 5 ثواني
    });
});
