document.addEventListener("DOMContentLoaded", () => {

  if (typeof statsData === "undefined") return;

  const COLORS = {
    sessions: "#38bdf8",   // light blue
    commands: "#22c55e",   // cyber green
    donut1: "#22c55e",
    donut2: "#38bdf8",
    donut3: "#2dd4bf"
  };

  const baseOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        labels: { color: "#e5e7eb" }
      }
    },
    scales: {
      x: {
        ticks: { color: "#94a3b8" },
        grid: { color: "rgba(255,255,255,0.06)" }
      },
      y: {
        ticks: { color: "#94a3b8" },
        grid: { color: "rgba(255,255,255,0.06)" }
      }
    }
  };

  /* ===== Sessions (Light Blue) ===== */
  new Chart(document.getElementById("sessionsChart"), {
    type: "line",
    data: {
      labels: Object.keys(statsData),
      datasets: [{
        label: "Sessions",
        data: Object.values(statsData).map(s => s.sessions),
        borderColor: COLORS.sessions,
        backgroundColor: "rgba(56,189,248,0.3)",
        pointBackgroundColor: "#ffffff",
        borderWidth: 3,
        fill: true,
        tension: 0.45
      }]
    },
    options: baseOptions
  });

  /* ===== Commands (Cyber Green) ===== */
  new Chart(document.getElementById("commandsChart"), {
    type: "line",
    data: {
      labels: Object.keys(statsData),
      datasets: [{
        label: "Commands",
        data: Object.values(statsData).map(s => s.commands),
        borderColor: COLORS.commands,
        backgroundColor: "rgba(34,197,94,0.3)",
        pointBackgroundColor: "#ffffff",
        borderWidth: 3,
        fill: true,
        tension: 0.45
      }]
    },
    options: baseOptions
  });

  /* ===== Doughnut (Cyber Palette) ===== */
  const t1 = Object.values(statsData).reduce((a,b)=>a+b.high,0);
  const t2 = Object.values(statsData).reduce((a,b)=>a+b.medium,0);
  const t3 = Object.values(statsData).reduce((a,b)=>a+b.low,0);

  new Chart(document.getElementById("severityChart"), {
    type: "doughnut",
    data: {
      labels: ["High", "Medium", "Low"],
      datasets: [{
        data: [t1, t2, t3],
        backgroundColor: [
          COLORS.donut1,
          COLORS.donut2,
          COLORS.donut3
        ],
        borderWidth: 2,
        borderColor: "#020617"
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "bottom",
          labels: { color: "#e5e7eb" }
        }
      }
    }
  });

});
