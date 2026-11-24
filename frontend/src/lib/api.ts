export interface RecentActivity {
  message_id: string;
  sender: string;
  subject: string;
  verdict: string;
  action: string;
  risk_score: number;
  analyzed_at: string;
}

export interface DashboardStats {
  total_scanned: number;
  safe: number;
  suspicious: number;
  malicious: number;
  inconclusive: number;
  threats_detected: number;
  threat_percentage: number;
  recent_activity: RecentActivity[];
}

export async function getDashboardStats(): Promise<DashboardStats> {
  const response = await fetch(
    "/api/backend/api/v1/dashboard/stats",
    { cache: "no-store" }
  );

  if (!response.ok) {
    throw new Error("Failed to retrieve dashboard statistics.");
  }

  return response.json();
}

export async function scanEmails(maxResults = 5) {
  const response = await fetch(
    `/api/backend/api/v1/gmail/scan?max_results=${maxResults}`,
    { method: "POST" }
  );

  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.detail || "Gmail scanning failed.");
  }

  return data;
}