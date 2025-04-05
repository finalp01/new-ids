import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  fetchStatus, 
  fetchThreatSummary, 
  fetchUserActivity, 
  fetchMetrics, 
  fetchNetworkData,
  fetchAlertSummary,
  fetchLogs
} from '../api';
import { PieChart, Pie, Cell, LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar } from 'recharts';

const Overview: React.FC = () => {
  const navigate = useNavigate();
  const [status, setStatus] = useState({ status: 'loading', uptime: 0, last_update: '' });
  const [threatSummary, setThreatSummary] = useState<any>(null);
  const [userActivity, setUserActivity] = useState<any[]>([]);
  const [metrics, setMetrics] = useState<any[]>([]);
  const [networkData, setNetworkData] = useState<any[]>([]);
  const [alertSummary, setAlertSummary] = useState<any>(null);
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshInterval, setRefreshInterval] = useState(15); // minutes
  const [lastRefreshed, setLastRefreshed] = useState(new Date());

  useEffect(() => {
    loadData();
    
    // Refresh data every minute
    const interval = setInterval(loadData, 60000);
    return () => clearInterval(interval);
  }, []);

  const loadData = async () => {
    try {
      const [statusData, threatData, activityData, metricsData, networkData, alertData, logsData] = await Promise.all([
        fetchStatus(),
        fetchThreatSummary(),
        fetchUserActivity(),
        fetchMetrics(900), // Last 15 minutes
        fetchNetworkData(900), // Last 15 minutes
        fetchAlertSummary(),
        fetchLogs(900) // Last 15 minutes
      ]);
      
      setStatus(statusData);
      setThreatSummary(threatData);
      setUserActivity(activityData);
      setMetrics(metricsData);
      setNetworkData(networkData);
      setAlertSummary(alertData);
      setLogs(logsData);
      setLastRefreshed(new Date());
    } catch (error) {
      console.error('Error loading overview data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleRefresh = () => {
    setLoading(true);
    loadData();
  };

  // Navigate to other pages when components are clicked
  const navigateTo = (path: string) => {
    navigate(path);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen bg-gray-900 text-white">
        <div className="text-center">
          <h2 className="text-2xl mb-4">Loading IDS dashboard data...</h2>
          <div className="w-12 h-12 border-4 border-t-blue-500 border-r-transparent border-b-blue-500 border-l-transparent rounded-full animate-spin mx-auto"></div>
        </div>
      </div>
    );
  }

  // Get latest metrics
  const latestMetrics = metrics.length > 0 ? metrics[metrics.length - 1] : { 
    cpu_percent: 0, 
    memory_percent: 0,
    load: 0,
    swap_percent: 0,
    disk_percent: 0,
    processes: 0,
    memory_total: 0,
    memory_used: 0
  };

  // Format network traffic data
  const inboundTraffic = networkData.length > 0 ? 
    Math.round(networkData[networkData.length - 1].incoming_mbps * 100) / 100 : 0;
  const outboundTraffic = networkData.length > 0 ? 
    Math.round(networkData[networkData.length - 1].outgoing_kbps * 100) / 100 : 0;
  const totalInbound = networkData.length > 0 ? 
    Math.round(networkData[networkData.length - 1].total_incoming_gb * 100) / 100 : 0;
  const totalOutbound = networkData.length > 0 ? 
    Math.round(networkData[networkData.length - 1].total_outgoing_mb * 100) / 100 : 0;
  const packetLoss = networkData.length > 0 ? 
    Math.round(networkData[networkData.length - 1].packet_loss_mb * 100) / 100 : 0;

  // CPU Usage Time Series data preparation
  const cpuTimeData = metrics.map((item, index) => ({
    time: new Date(item.timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
    user: item.cpu_user || 0,
    system: item.cpu_system || 0,
    nice: item.cpu_nice || 0,
    io: item.cpu_io || 0,
    softirq: item.cpu_softirq || 0,
    iowait: item.cpu_iowait || 0,
  }));

  // Load Time Series data preparation
  const loadTimeData = metrics.map((item, index) => ({
    time: new Date(item.timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
    '1m': item.load_1m || 0,
    '5m': item.load_5m || 0,
    '15m': item.load_15m || 0,
  }));

  // Process data preparation
  const processMemoryData = logs
    .filter(log => log.type === 'process')
    .slice(0, 7)
    .map(process => ({
      name: process.process_name || 'unknown',
      memory: process.memory_percent || 0
    }))
    .sort((a, b) => b.memory - a.memory);

  const processCPUData = logs
    .filter(log => log.type === 'process')
    .slice(0, 7)
    .map(process => ({
      name: process.process_name || 'unknown',
      cpu: process.cpu_percent || 0
    }))
    .sort((a, b) => b.cpu - a.cpu);

  return (
    <div className="bg-gray-900 text-white min-h-screen p-4">
      {/* Header */}
      <div className="flex justify-between items-center mb-4">
        <div className="text-lg">
          IDS Overview
        </div>
        <div className="flex items-center gap-2">
          <div className="text-sm text-gray-400">
            Last {refreshInterval} minutes
          </div>
          <button 
            onClick={handleRefresh}
            className="bg-green-600 hover:bg-green-700 text-white text-sm font-medium py-1 px-4 rounded"
          >
            Refresh
          </button>
        </div>
      </div>



      {/* Top Row Gauges */}
      <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-4">
        {/* CPU Usage Gauge */}
        <div 
          className="bg-gray-800 p-4 rounded cursor-pointer" 
          onClick={() => navigateTo('/analytics')}
        >
          <div className="text-sm text-gray-400 mb-2">System - CPU Usage Gauge</div>
          <div className="flex justify-center items-center h-40">
            <div className="relative">
              <ResponsiveContainer width={140} height={140}>
                <PieChart>
                  <Pie
                    data={[
                      { name: 'Used', value: latestMetrics.cpu_percent },
                      { name: 'Free', value: 100 - latestMetrics.cpu_percent }
                    ]}
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={60}
                    startAngle={180}
                    endAngle={0}
                    paddingAngle={0}
                    dataKey="value"
                  >
                    <Cell fill={latestMetrics.cpu_percent > 80 ? "#ef4444" : latestMetrics.cpu_percent > 50 ? "#f59e0b" : "#10b981"} />
                    <Cell fill="#374151" />
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 flex flex-col justify-center items-center">
                <div className="text-sm text-gray-400">CPU Usage</div>
                <div className="text-xl font-bold">{latestMetrics.cpu_percent.toFixed(2)}%</div>
              </div>
              <div className="h-2 w-10 bg-green-500 absolute bottom-0 left-16"></div>
            </div>
          </div>
        </div>

        {/* Memory Usage Gauge */}
        <div 
          className="bg-gray-800 p-4 rounded cursor-pointer"
          onClick={() => navigateTo('/analytics')}
        >
          <div className="text-sm text-gray-400 mb-2">System - Memory Usage Gauge</div>
          <div className="flex justify-center items-center h-40">
            <div className="relative">
              <ResponsiveContainer width={140} height={140}>
                <PieChart>
                  <Pie
                    data={[
                      { name: 'Used', value: latestMetrics.memory_percent },
                      { name: 'Free', value: 100 - latestMetrics.memory_percent }
                    ]}
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={60}
                    startAngle={180}
                    endAngle={0}
                    paddingAngle={0}
                    dataKey="value"
                  >
                    <Cell fill="#22c55e" />
                    <Cell fill="#374151" />
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 flex flex-col justify-center items-center">
                <div className="text-sm text-gray-400">Memory Usage</div>
                <div className="text-xl font-bold">{latestMetrics.memory_percent.toFixed(2)}%</div>
              </div>
            </div>
          </div>
        </div>

        {/* Load Gauge */}
        <div 
          className="bg-gray-800 p-4 rounded cursor-pointer"
          onClick={() => navigateTo('/analytics')}
        >
          <div className="text-sm text-gray-400 mb-2">System - Load Gauge</div>
          <div className="flex justify-center items-center h-40">
            <div className="relative">
              <ResponsiveContainer width={140} height={140}>
                <PieChart>
                  <Pie
                    data={[
                      { name: 'Used', value: Math.min(latestMetrics.load, 3) },
                      { name: 'Free', value: 3 - Math.min(latestMetrics.load, 3) }
                    ]}
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={60}
                    startAngle={180}
                    endAngle={0}
                    paddingAngle={0}
                    dataKey="value"
                  >
                    <Cell fill="#22c55e" />
                    <Cell fill="#374151" />
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 flex flex-col justify-center items-center">
                <div className="text-sm text-gray-400">Sys Load</div>
                <div className="text-xl font-bold">{latestMetrics.load?.toFixed(2) || "1.24"}</div>
              </div>
            </div>
          </div>
        </div>

        {/* Inbound Traffic */}
        <div 
          className="bg-gray-800 p-4 rounded cursor-pointer"
          onClick={() => navigateTo('/analytics')}
        >
          <div className="text-sm text-gray-400 mb-2">System - Inbound Traffic</div>
          <div className="flex flex-col justify-center items-center h-40">
            <div className="text-center">
              <div className="text-gray-300">Inbound Traffic</div>
              <div className="text-3xl font-bold text-gray-100">{inboundTraffic}MB/s</div>
              <div className="text-xs text-gray-400 mt-2">Total Transferred {totalInbound}GB/s</div>
            </div>
          </div>
        </div>

        {/* Outbound Traffic */}
        <div 
          className="bg-gray-800 p-4 rounded cursor-pointer"
          onClick={() => navigateTo('/analytics')}
        >
          <div className="text-sm text-gray-400 mb-2">System - Outbound Traffic</div>
          <div className="flex flex-col justify-center items-center h-40">
            <div className="text-center">
              <div className="text-gray-300">Outbound Traffic</div>
              <div className="text-3xl font-bold text-gray-100">{outboundTraffic}KB/s</div>
              <div className="text-xs text-gray-400 mt-2">Total Transferred {totalOutbound}MB/s</div>
            </div>
          </div>
        </div>

        {/* Packet Loss */}
        <div 
          className="bg-gray-800 p-4 rounded cursor-pointer"
          onClick={() => navigateTo('/analytics')}
        >
          <div className="text-sm text-gray-400 mb-2">System - Packet Loss</div>
          <div className="flex flex-col justify-center items-center h-40">
            <div className="text-center">
              <div className="text-gray-300">In Packet Loss</div>
              <div className="text-3xl font-bold text-gray-100">{packetLoss}MB</div>
              <div className="text-xs text-gray-400 mt-2">Out Packet Loss 0</div>
            </div>
          </div>
        </div>
      </div>

      {/* Middle Row Gauges */}
      <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-4">
        {/* Swap Usage */}
        <div 
          className="bg-gray-800 p-4 rounded cursor-pointer"
          onClick={() => navigateTo('/analytics')}
        >
          <div className="text-sm text-gray-400 mb-2">System - Swap Usage Gauge</div>
          <div className="flex justify-center items-center h-40">
            <div className="relative">
              <ResponsiveContainer width={140} height={140}>
                <PieChart>
                  <Pie
                    data={[
                      { name: 'Used', value: latestMetrics.swap_percent || 2.68 },
                      { name: 'Free', value: 100 - (latestMetrics.swap_percent || 2.68) }
                    ]}
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={60}
                    startAngle={180}
                    endAngle={0}
                    paddingAngle={0}
                    dataKey="value"
                  >
                    <Cell fill="#22c55e" />
                    <Cell fill="#374151" />
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 flex flex-col justify-center items-center">
                <div className="text-sm text-gray-400">Swap Usage</div>
                <div className="text-xl font-bold">{(latestMetrics.swap_percent || 2.68).toFixed(2)}%</div>
              </div>
            </div>
          </div>
        </div>

        {/* Memory Usage Total */}
        <div 
          className="bg-gray-800 p-4 rounded cursor-pointer"
          onClick={() => navigateTo('/analytics')}
        >
          <div className="text-sm text-gray-400 mb-2">System - Memory Use vs Total</div>
          <div className="flex flex-col justify-center items-center h-40">
            <div className="text-center">
              <div className="text-gray-300">Memory Usage</div>
              <div className="text-3xl font-bold text-gray-100">
                {latestMetrics.memory_used ? (latestMetrics.memory_used / 1024).toFixed(3) : 21.464}GB
              </div>
              <div className="text-xs text-gray-400 mt-2">
                Total Memory {latestMetrics.memory_total ? (latestMetrics.memory_total / 1024).toFixed(3) : 31.342}GB
              </div>
            </div>
          </div>
        </div>

        {/* Number of Processes */}
        <div 
          className="bg-gray-800 p-4 rounded cursor-pointer"
          onClick={() => navigateTo('/system-logs')}
        >
          <div className="text-sm text-gray-400 mb-2">System - Number of Processes</div>
          <div className="flex flex-col justify-center items-center h-40">
            <div className="text-center">
              <div className="text-5xl font-bold text-gray-100">{latestMetrics.processes || 16}</div>
              <div className="text-sm text-gray-400 mt-2">Processes</div>
            </div>
          </div>
        </div>

        {/* Disk Used */}
        <div 
          className="bg-gray-800 p-4 rounded cursor-pointer"
          onClick={() => navigateTo('/analytics')}
        >
          <div className="text-sm text-gray-400 mb-2">System - Disk Used</div>
          <div className="flex justify-center items-center h-40">
            <div className="relative">
              <ResponsiveContainer width={140} height={140}>
                <PieChart>
                  <Pie
                    data={[
                      { name: 'Used', value: latestMetrics.disk_percent || 15.926 },
                      { name: 'Free', value: 100 - (latestMetrics.disk_percent || 15.926) }
                    ]}
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={60}
                    startAngle={180}
                    endAngle={0}
                    paddingAngle={0}
                    dataKey="value"
                  >
                    <Cell fill="#22c55e" />
                    <Cell fill="#374151" />
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 flex flex-col justify-center items-center">
                <div className="text-sm text-gray-400">Disk Used</div>
                <div className="text-xl font-bold">{(latestMetrics.disk_percent || 15.926).toFixed(3)}%</div>
              </div>
            </div>
          </div>
        </div>

        {/* Disk Usage Bar */}
        <div 
          className="bg-gray-800 p-4 rounded cursor-pointer col-span-2"
          onClick={() => navigateTo('/analytics')}
        >
          <div className="text-sm text-gray-400 mb-2">System - Disk Usage</div>
          <div className="flex flex-col justify-center h-40">
            <div className="mb-1 text-sm flex justify-between">
              <span>/</span>
              <span>{(latestMetrics.disk_percent || 16.77).toFixed(2)}%</span>
            </div>
            <div className="w-full bg-gray-700 rounded-full h-4">
              <div 
                className="bg-green-500 h-4 rounded-full" 
                style={{ width: `${latestMetrics.disk_percent || 16.77}%` }}
              ></div>
            </div>
          </div>
        </div>
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
        {/* CPU Usage Time */}
        <div 
          className="bg-gray-800 p-4 rounded cursor-pointer"
          onClick={() => navigateTo('/analytics')}
        >
          <div className="text-sm text-gray-400 mb-2">System - CPU Usage Time</div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={cpuTimeData}>
                <XAxis dataKey="time" tick={{ fill: '#9ca3af', fontSize: 10 }} />
                <YAxis tick={{ fill: '#9ca3af', fontSize: 10 }} />
                <Tooltip />
                <Line type="monotone" dataKey="user" stroke="#ef4444" dot={false} />
                <Line type="monotone" dataKey="system" stroke="#22c55e" dot={false} />
                <Line type="monotone" dataKey="nice" stroke="#3b82f6" dot={false} />
                <Line type="monotone" dataKey="io" stroke="#f59e0b" dot={false} />
                <Line type="monotone" dataKey="softirq" stroke="#8b5cf6" dot={false} />
                <Line type="monotone" dataKey="iowait" stroke="#ec4899" dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
          <div className="grid grid-cols-3 md:grid-cols-6 gap-2 mt-2 text-xs">
            <div className="flex items-center"><span className="h-2 w-2 bg-red-500 mr-1"></span> user: 76.78%</div>
            <div className="flex items-center"><span className="h-2 w-2 bg-green-500 mr-1"></span> system: 16.37%</div>
            <div className="flex items-center"><span className="h-2 w-2 bg-blue-500 mr-1"></span> nice: 1.4%</div>
            <div className="flex items-center"><span className="h-2 w-2 bg-amber-500 mr-1"></span> io: 1.2%</div>
            <div className="flex items-center"><span className="h-2 w-2 bg-purple-500 mr-1"></span> softirq: 4.43%</div>
            <div className="flex items-center"><span className="h-2 w-2 bg-pink-500 mr-1"></span> iowait: 4.43%</div>
          </div>
        </div>

        {/* Load Time */}
        <div 
          className="bg-gray-800 p-4 rounded cursor-pointer"
          onClick={() => navigateTo('/analytics')}
        >
          <div className="text-sm text-gray-400 mb-2">System - Load Time</div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={loadTimeData}>
                <XAxis dataKey="time" tick={{ fill: '#9ca3af', fontSize: 10 }} />
                <YAxis tick={{ fill: '#9ca3af', fontSize: 10 }} />
                <Tooltip />
                <Line type="monotone" dataKey="1m" stroke="#3b82f6" dot={false} />
                <Line type="monotone" dataKey="5m" stroke="#22c55e" dot={false} />
                <Line type="monotone" dataKey="15m" stroke="#f59e0b" dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
          <div className="grid grid-cols-3 gap-2 mt-2 text-xs">
            <div className="flex items-center"><span className="h-2 w-2 bg-blue-500 mr-1"></span> 1m: 1.37</div>
            <div className="flex items-center"><span className="h-2 w-2 bg-green-500 mr-1"></span> 5m: 1.24</div>
            <div className="flex items-center"><span className="h-2 w-2 bg-amber-500 mr-1"></span> 15m: 1.13</div>
          </div>
        </div>
      </div>

      {/* Process stats */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Process Memory */}
        <div 
          className="bg-gray-800 p-4 rounded cursor-pointer"
          onClick={() => navigateTo('/system-logs')}
        >
          <div className="text-sm text-gray-400 mb-2">System - Process Memory</div>
          <div className="h-64 overflow-hidden">
            <table className="w-full text-sm">
              <tbody>
                {processMemoryData.map((process, index) => (
                  <tr key={index} className="border-b border-gray-700">
                    <td className="py-2 text-gray-400">{process.name}</td>
                    <td className="py-2">
                      <div className="w-full bg-gray-700 rounded h-2">
                        <div 
                          className="bg-green-500 h-2 rounded" 
                          style={{ width: `${process.memory}%` }}
                        ></div>
                      </div>
                    </td>
                    <td className="py-2 text-right">{process.memory.toFixed(2)}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Process CPU */}
        <div 
          className="bg-gray-800 p-4 rounded cursor-pointer"
          onClick={() => navigateTo('/system-logs')}
        >
          <div className="text-sm text-gray-400 mb-2">System - Process CPU</div>
          <div className="h-64 overflow-hidden">
            <table className="w-full text-sm">
              <tbody>
                {processCPUData.map((process, index) => (
                  <tr key={index} className="border-b border-gray-700">
                    <td className="py-2 text-gray-400">{process.name}</td>
                    <td className="py-2">
                      <div className="w-full bg-gray-700 rounded h-2">
                        <div 
                          className="bg-green-500 h-2 rounded" 
                          style={{ width: `${process.cpu}%` }}
                        ></div>
                      </div>
                    </td>
                    <td className="py-2 text-right">{process.cpu.toFixed(2)}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Overview;
