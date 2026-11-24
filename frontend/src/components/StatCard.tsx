import { ReactNode } from "react";

interface Props {
  title: string;
  value: number | string;
  description: string;
  icon: ReactNode;
  color: string;
}

export default function StatCard({
  title,
  value,
  description,
  icon,
  color,
}: Props) {
  return (
    <div className="stat-card">
      <div className="stat-top">
        <span>{title}</span>
        <div className={`stat-icon ${color}`}>{icon}</div>
      </div>

      <div className="stat-value">{value}</div>

      <div className="stat-description">{description}</div>
    </div>
  );
}