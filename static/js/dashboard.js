const chartData = window.CTI_CHART_DATA || {};

function buildChart(canvasId, type, dataObject) {
    const canvas = document.getElementById(canvasId);
    if (!canvas || !dataObject) return;

    const labels = Object.keys(dataObject);
    const values = Object.values(dataObject);

    if (labels.length === 0) {
        const empty = document.createElement("p");
        empty.className = "text-secondary";
        empty.textContent = "No data available.";
        canvas.replaceWith(empty);
        return;
    }

    new Chart(canvas, {
        type,
        data: {
            labels,
            datasets: [{
                label: "Count",
                data: values,
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    display: type !== "bar",
                    labels: { color: "#dbe7f8" }
                }
            },
            scales: type === "bar" ? {
                x: { ticks: { color: "#dbe7f8" }, grid: { color: "rgba(255,255,255,0.08)" } },
                y: { ticks: { color: "#dbe7f8", precision: 0 }, grid: { color: "rgba(255,255,255,0.08)" } }
            } : {}
        }
    });
}

buildChart("priorityChart", "doughnut", chartData.priority);
buildChart("severityChart", "doughnut", chartData.severity);
buildChart("exploitConfidenceChart", "doughnut", chartData.exploit_confidence);
buildChart("vendorChart", "bar", chartData.top_vendors);
buildChart("productChart", "bar", chartData.top_products);
buildChart("threatRefChart", "bar", chartData.top_threat_refs);

const searchInput = document.getElementById("cveSearch");
const table = document.getElementById("cveTable");

if (searchInput && table) {
    searchInput.addEventListener("input", () => {
        const query = searchInput.value.toLowerCase();
        const rows = table.querySelectorAll("tbody tr.cve-row");

        rows.forEach((row) => {
            const summaryRow = row.nextElementSibling && row.nextElementSibling.classList.contains("summary-row") ? row.nextElementSibling : null;
            const text = row.innerText.toLowerCase();
            const visible = text.includes(query);
            row.style.display = visible ? "" : "none";
            if (!visible && summaryRow) summaryRow.style.display = "none";
            if (visible && summaryRow && !summaryRow.classList.contains("d-none")) summaryRow.style.display = "";
        });
    });
}

document.querySelectorAll(".detail-toggle").forEach((button) => {
    button.addEventListener("click", () => {
        const row = button.closest("tr");
        const summaryRow = row.nextElementSibling;
        if (!summaryRow || !summaryRow.classList.contains("summary-row")) return;
        summaryRow.classList.toggle("d-none");
        summaryRow.style.display = summaryRow.classList.contains("d-none") ? "none" : "";
        button.textContent = summaryRow.classList.contains("d-none") ? "details" : "hide";
    });
});
