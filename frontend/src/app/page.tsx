"use client";

import { useEffect, useState } from "react";
import {
  ShieldCheck,
  AlertTriangle,
  ShieldAlert,
  Mail,
  RefreshCw,
  ScanSearch,
} from "lucide-react";

import Sidebar from "@/components/Sidebar";
import StatCard from "@/components/StatCard";
import ThreatChart from "@/components/ThreatChart";

import {
  getDashboardStats,
  DashboardStats,
  scanEmails,
} from "@/lib/api";

export default function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [scanning, setScanning] = useState(false);
  const [scanMessage, setScanMessage] = useState("");

  async function loadStats() {
    try {
      setError("");
      const data = await getDashboardStats();
      setStats(data);
    } catch {
      setError("Unable to connect to the PhishGuard backend.");
    } finally {
      setLoading(false);
    }
  }

  async function handleScan() {
    try {
      setScanning(true);
      setScanMessage("");

      const result = await scanEmails(5);

      setScanMessage(
        `Scan completed. ${result.successful ?? 0} successful, ${
          result.failed ?? 0
        } failed.`
      );

      await loadStats();
    } catch (err) {
      setScanMessage(
        err instanceof Error ? err.message : "Gmail scan failed."
      );
    } finally {
      setScanning(false);
    }
  }

  useEffect(() => {
    loadStats();
  }, []);

  return (
    <div className="app-shell">
      <Sidebar />

      <main className="main-content">
        <header className="topbar">
          <div>
            <p className="breadcrumb">PHISHGUARD / OVERVIEW</p>
            <h2>Security Overview</h2>
            <p className="page-subtitle">
              Monitor email threats, detection results and security activity.
            </p>
          </div>

          <button
            className="scan-button"
            onClick={handleScan}
            disabled={scanning}
          >
            <ScanSearch size={18} />
            {scanning ? "Scanning..." : "Scan Gmail"}
          </button>
        </header>

        {scanMessage && (
          <div className="notice">{scanMessage}</div>
        )}

        {error && (
          <div className="error-box">
            {error}
            <button onClick={loadStats}>Retry</button>
          </div>
        )}

        <section className="stats-grid">
          <StatCard
            title="Total Emails Scanned"
            value={loading ? "..." : stats?.total_scanned ?? 0}
            description="Total analysed emails"
            icon={<Mail size={21} />}
            color="blue"
          />

          <StatCard
            title="Safe Emails"
            value={loading ? "..." : stats?.safe ?? 0}
            description="Classified as safe"
            icon={<ShieldCheck size={21} />}
            color="green"
          />

          <StatCard
            title="Suspicious Emails"
            value={loading ? "..." : stats?.suspicious ?? 0}
            description="Require user attention"
            icon={<AlertTriangle size={21} />}
            color="orange"
          />

          <StatCard
            title="Malicious Emails"
            value={loading ? "..." : stats?.malicious ?? 0}
            description="Classified as malicious"
            icon={<ShieldAlert size={21} />}
            color="red"
          />
        </section>

        <section className="overview-grid">
          <ThreatChart
            safe={stats?.safe ?? 0}
            suspicious={stats?.suspicious ?? 0}
            malicious={stats?.malicious ?? 0}
            inconclusive={stats?.inconclusive ?? 0}
          />

          <div className="threat-summary">
            <div className="section-heading">
              <div>
                <h3>Threat Intelligence Summary</h3>
                <p>Current analysis statistics</p>
              </div>
            </div>

            <div className="summary-highlight">
              <span>Threat detection rate</span>
              <strong>
                {stats?.threat_percentage ?? 0}%
              </strong>
            </div>

            <div className="summary-row">
              <span>Threats detected</span>
              <strong>{stats?.threats_detected ?? 0}</strong>
            </div>

            <div className="summary-row">
              <span>Inconclusive results</span>
              <strong>{stats?.inconclusive ?? 0}</strong>
            </div>

            <div className="summary-row">
              <span>Total analysed</span>
              <strong>{stats?.total_scanned ?? 0}</strong>
            </div>
          </div>
        </section>

        <section className="activity-panel">
          <div className="section-heading">
            <div>
              <h3>Recent Security Activity</h3>
              <p>Latest analysed email reports</p>
            </div>

            <button className="refresh-button" onClick={loadStats}>
              <RefreshCw size={16} />
              Refresh
            </button>
          </div>

          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Sender</th>
                  <th>Subject</th>
                  <th>Verdict</th>
                  <th>Action</th>
                  <th>Risk Score</th>
                </tr>
              </thead>

              <tbody>
                {stats?.recent_activity?.length ? (
                  stats.recent_activity.map((email) => (
                    <tr key={email.message_id}>
                      <td>{email.sender}</td>
                      <td>{email.subject || "No subject"}</td>
                      <td>
                        <span
                          className={`badge ${email.verdict}`}
                        >
                          {email.verdict}
                        </span>
                      </td>
                      <td>{email.action}</td>
                      <td>{email.risk_score}/100</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={5} className="empty-state">
                      {loading
                        ? "Loading activity..."
                        : "No analysed emails yet. Run a Gmail scan to get started."}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        <footer className="dashboard-footer">
          PhishGuard · Agentic AI-Based Zero-Trust Email Security Gateway
        </footer>
      </main>
    </div>
  );
}