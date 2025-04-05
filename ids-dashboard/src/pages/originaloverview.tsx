import React, { useState, useEffect } from 'react';
import NetworkFlow from '../components/NetworkFlow';
import ThreatSummary from '../components/ThreatSummary';
import UserActivityLog from '../components/UserActivityLog';
import SystemMetrics from '../components/SystemMetrics';
import { fetchStatus, fetchThreatSummary, fetchUserActivity, fetchMetrics } from '../api';

const Overview: React.FC = () => {
  const [status, setStatus] = useState<{ status: string; uptime: number; last_update: string }>({ 
    status: 'loading', 
    uptime: 0, 
    last_update: '' 
  });
  const [threatSummary, setThreatSummary] = useState<any>(null);
  const [userActivity, setUserActivity] = useState<any[]>([]);
  const [metrics, setMetrics] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadData = async () => {
      try {
        const [statusData, threatData, activityData, metricsData] = await Promise.all([
          fetchStatus(),
          fetchThreatSummary(),
          fetchUserActivity(),
          fetchMetrics(300) // Last 5 minutes
        ]);
        
        setStatus(statusData);
        setThreatSummary(threatData);
        setUserActivity(activityData);
        setMetrics(metricsData);
      } catch (error) {
        console.error('Error loading overview data:', error);
      } finally {
        setLoading(false);
      }
    };

    loadData();
    
    // Refresh data every 30 seconds
    const interval = setInterval(loadData, 30000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return <div className="p-6">Loading dashboard data...</div>;
  }

  // Calculate the latest metrics for CPU and memory
  const latestMetrics = metrics.length > 0 ? metrics[metrics.length - 1] : { cpu_percent: 0, memory_percent: 0 };

  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-4">
        <div>
          <h1 className="text-2xl font-bold">Network overview</h1>
          <p className="text-gray-600">Realtime monitoring and analysis</p>
        </div>
        <div className="flex gap-4">
          <div className="relative">
            <input 
              type="text" 
              placeholder="Search..." 
              className="border rounded-md py-2 px-4"
            />
          </div>
          <button className="bg-white px-4 py-2 rounded-md">
            Notifications
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="bg-white p-4 rounded-md">
          <h2 className="text-xl font-semibold mb-2">Network flow</h2>
          <NetworkFlow />
        </div>
        
        <div className="bg-white p-4 rounded-md">
          <div className="flex flex-col items-center">
            <h2 className="text-6xl font-bold">{threatSummary?.total_alerts || 0}</h2>
            <div className="flex gap-2 mt-2">
              <span className="bg-red-600 text-white px-3 py-1 rounded-full">Phishing site</span>
              <span className="bg-red-600 text-white px-3 py-1 rounded-full">Malware</span>
            </div>
          </div>
        </div>
        
        <div className="bg-white p-4 rounded-md">
          <h2 className="text-xl font-semibold mb-2">User activity log</h2>
          <UserActivityLog activities={userActivity.slice(0, 3)} />
        </div>
        
        <div className="bg-white p-4 rounded-md">
          <SystemMetrics 
            cpuUsage={latestMetrics.cpu_percent} 
            memoryUsage={latestMetrics.memory_percent} 
          />
        </div>
      </div>
    </div>
  );
};

export default Overview;