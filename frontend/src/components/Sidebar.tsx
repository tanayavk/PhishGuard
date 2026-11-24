"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Shield,
  LayoutDashboard,
  Mail,
  Search,
  Bot,
  FileText,
  Settings,
  Activity,
} from "lucide-react";

const navigation = [
  { name: "Overview", href: "/", icon: LayoutDashboard },
  { name: "Gmail Scanner", href: "/scanner", icon: Mail },
  { name: "Threat Analysis", href: "/emails", icon: Search },
  { name: "Agent Investigation", href: "/investigation", icon: Bot },
  { name: "Audit & Reports", href: "/audit", icon: FileText },
];

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-icon">
          <Shield size={25} />
        </div>

        <div>
          <h1>PhishGuard</h1>
          <span>ZERO-TRUST SECURITY</span>
        </div>
      </div>

      <div className="nav-label">MAIN MENU</div>

      <nav className="navigation">
        {navigation.map((item) => {
          const Icon = item.icon;
          const active = pathname === item.href;

          return (
            <Link
              key={item.name}
              href={item.href}
              className={`nav-item ${active ? "active" : ""}`}
            >
              <Icon size={19} />
              <span>{item.name}</span>
            </Link>
          );
        })}
      </nav>

      <div className="sidebar-bottom">
        <div className="system-status">
          <Activity size={17} />
          <div>
            <strong>Backend integration</strong>
            <span>FastAPI service</span>
          </div>
          <span className="status-dot" />
        </div>

        <div className="version">PhishGuard v1.0</div>
      </div>
    </aside>
  );
}