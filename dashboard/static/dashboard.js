// Search IP
document.getElementById("searchInput").addEventListener("keyup", function () {
    const filter = this.value.toLowerCase();
    const rows = document.querySelectorAll("#honeypotTable tbody tr");

    rows.forEach(row => {
        const ip = row.cells[0].innerText.toLowerCase();
        row.style.display = ip.includes(filter) ? "" : "none";
    });
});

// Export CSV
function exportTable() {
    let csv = [];
    const rows = document.querySelectorAll("#honeypotTable tr");

    rows.forEach(row => {
        let cols = row.querySelectorAll("td, th");
        let rowData = [];
        cols.forEach(col => {
            rowData.push('"' + col.innerText.replace(/"/g, '""') + '"');
        });
        csv.push(rowData.join(","));
    });

    const blob = new Blob([csv.join("\n")], { type: "text/csv" });
    const url = window.URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;
    a.download = "honeypot_logs.csv";
    a.click();
}
