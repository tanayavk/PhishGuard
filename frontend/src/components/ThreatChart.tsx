"use client";

import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
} from "recharts";

interface Props {
  safe: number;
  suspicious: number;
  malicious: number;
  inconclusive: number;
}

const COLORS = ["#22c55e", "#f59e0b", "#ef4444", "#64748b"];

export default function ThreatChart({
  safe,
  suspicious,
  malicious,
  inconclusive,
}: Props) {
  const data = [
    { name: "Safe", value: safe },
    { name: "Suspicious", value: suspicious },
    { name: "Malicious", value: malicious },
    { name: "Inconclusive", value: inconclusive },
  ];

  return (
    <div className="chart-container">
      <div className="section-heading">
        <div>
          <h3>Threat Distribution</h3>
          <p>Classification of analysed emails</p>
        </div>
      </div>

      <div className="chart-content">
        <div className="chart">
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie
                data={data}
                dataKey="value"
                nameKey="name"
                innerRadius={58}
                outerRadius={85}
                paddingAngle={4}
              >
                {data.map((entry, index) => (
                  <Cell
                    key={entry.name}
                    fill={COLORS[index]}
                  />
                ))}
              </Pie>

              <Tooltip
                contentStyle={{
                  background: "#111c30",
                  border: "1px solid #26354d",
                  borderRadius: "10px",
                  color: "#fff",
                }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-legend">
          {data.map((item, index) => (
            <div className="legend-item" key={item.name}>
              <span
                className="legend-dot"
                style={{ background: COLORS[index] }}
              />
              <span>{item.name}</span>
              <strong>{item.value}</strong>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}