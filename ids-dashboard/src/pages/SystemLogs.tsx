import React, { useState, useEffect } from 'react';
import { fetchLogs, fetchAlertSummary, fetchThreatSummary } from '../api';
import { Link } from 'react-router-dom';

interface LogEntry {
  timestamp: string;
  source: string;
  content: string;
  severity?: 'low' | 'medium' | 'high' | 'critical';
  type?: string;
}

interface AlertSummary {
  total_alerts: number;
  by_type: Record<string, number>;
  by_severity: Record<string, number>;
}

interface ThreatSummary {
  total_alerts: number;
  alerts_last_hour: number;
  alerts_last_day: number;
  severity_counts: Record<string, number>;
  top_threats: Array<{ type: string; count: number }>;
}

const SystemLogs: React.FC = () => {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState(3600); // Default: last hour (in seconds)
  const [filter, setFilter] = useState('');
  const [sortField, setSortField] = useState<'timestamp' | 'source' | 'severity'>('timestamp');
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('desc');
  const [alertSummary, setAlertSummary] = useState<AlertSummary | null>(null);
  const [threatSummary, setThreatSummary] = useState<ThreatSummary | null>(null);
  const [selectedSeverity, setSelectedSeverity] = useState<string | null>(null);

  // Get severity class for coloring
  const getSeverityClass = (severity?: string) => {
    switch(severity) {
      case 'critical': return 'bg-red-100 text-red-800 font-medium';
      case 'high': return 'bg-orange-100 text-orange-800 font-medium';
      case 'medium': return 'bg-yellow-100 text-yellow-800 font-medium';
      case 'low': return 'bg-green-100 text-green-800 font-medium';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  // Load logs, alert summary, and threat summary
  useEffect(() => {
    const loadData = async () => {
      try {
        setLoading(true);
        const [logsData, alertData, threatData] = await Promise.all([
          fetchLogs(timeRange),
          fetchAlertSummary(),
          fetchThreatSummary()
        ]);
        
        // Enhance log data with severity and type if not present
        const enhancedLogs = logsData.map(log => {
          if (!log.severity) {
            // Assign severity based on content keywords (simple example)
            if (log.content.toLowerCase().includes('critical')) {
              log.severity = 'critical';
            } else if (log.content.toLowerCase().includes('alert') || log.content.toLowerCase().includes('warning')) {
              log.severity = 'high';
            } else if (log.content.toLowerCase().includes('notice')) {
              log.severity = 'medium';
            } else {
              log.severity = 'low';
            }
          }
          
          if (!log.type) {
            // Assign type based on source or content
            if (log.source.includes('ids') || log.source.includes('snort')) {
              log.type = 'intrusion';
            } else if (log.source.includes('auth')) {
              log.type = 'authentication';
            } else if (log.source.includes('fw') || log.source.includes('firewall')) {
              log.type = 'firewall';
            } else {
              log.type = 'system';
            }
          }
          
          return log;
        });
        
        setLogs(enhancedLogs);
        setAlertSummary(alertData);
        setThreatSummary(threatData);
      } catch (error) {
        console.error('Error loading system logs data:', error);
      } finally {
        setLoading(false);
      }
    };
    
    loadData();
    const interval = setInterval(loadData, 15000);
    return () => clearInterval(interval);
  }, [timeRange]);

  // Filter and sort logs
  const processedLogs = React.useMemo(() => {
    let result = [...logs];
    
    // Filter by search term
    if (filter) {
      result = result.filter(log =>
        log.source.toLowerCase().includes(filter.toLowerCase()) ||
        log.content.toLowerCase().includes(filter.toLowerCase()) ||
        (log.type && log.type.toLowerCase().includes(filter.toLowerCase()))
      );
    }
    
    // Filter by severity if selected
    if (selectedSeverity) {
      result = result.filter(log => log.severity === selectedSeverity);
    }
    
    // Sort
    result.sort((a, b) => {
      let comparison = 0;
      
      if (sortField === 'timestamp') {
        comparison = new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime();
      } else if (sortField === 'source') {
        comparison = a.source.localeCompare(b.source);
      } else if (sortField === 'severity') {
        const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, undefined: 4 };
        comparison = (severityOrder[a.severity as keyof typeof severityOrder] || 4) - 
                    (severityOrder[b.severity as keyof typeof severityOrder] || 4);
      }
      
      return sortDirection === 'asc' ? comparison : -comparison;
    });
    
    return result;
  }, [logs, filter, sortField, sortDirection, selectedSeverity]);

  // Handle sort toggle
  const handleSort = (field: 'timestamp' | 'source' | 'severity') => {
    if (field === sortField) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('desc');
    }
  };


  // Calculate severity counts for the filtered logs
  const severityCounts = processedLogs.reduce((acc, log) => {
    const severity = log.severity || 'unknown';
    acc[severity] = (acc[severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  return (
    <div className="p-6 bg-gray-50 min-h-screen">
      {/* <Navigation /> */}
      
      <div className="mb-6">
        <div className="flex justify-between items-center">
          <div>
            <h1 className="text-2xl font-bold mb-1">IDS System Logs</h1>
            <p className="text-gray-600">Security logs and intrusion detection events</p>
          </div>
          <div className="flex items-center gap-2">
            <div className="text-sm text-gray-500">Auto-refresh: 15s</div>
            <button className="bg-green-50 hover:bg-green-100 text-green-700 px-3 py-1 rounded border border-green-200">
              Refresh
            </button>
          </div>
        </div>
      </div>
      
      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <div className="bg-white rounded-lg shadow p-4">
          <div className="text-sm font-medium text-gray-500 mb-1">Total Logs</div>
          <div className="text-2xl font-bold">{logs.length.toLocaleString()}</div>
        </div>
        
        <div className="bg-white rounded-lg shadow p-4">
          <div className="text-sm font-medium text-gray-500 mb-1">Recent Alerts</div>
          <div className="text-2xl font-bold">{threatSummary?.alerts_last_hour || 0}</div>
          <div className="text-xs text-gray-500">Last hour</div>
        </div>
        
        <div className="bg-white rounded-lg shadow p-4">
          <div className="text-sm font-medium text-gray-500 mb-1">Critical Events</div>
          <div className="text-2xl font-bold text-red-600">
            {threatSummary?.severity_counts?.critical || 0}
          </div>
        </div>
        
        <div className="bg-white rounded-lg shadow p-4">
          <div className="text-sm font-medium text-gray-500 mb-1">Top Threat</div>
          <div className="text-xl font-bold truncate">
            {threatSummary?.top_threats?.[0]?.type || 'None detected'}
          </div>
        </div>
      </div>
      
      {/* Controls */}
      <div className="flex flex-col md:flex-row justify-between mb-4 gap-4">
        <div className="flex flex-wrap gap-2">
          <button
            className={`px-4 py-2 rounded-md ${timeRange === 3600 ? 'bg-blue-600 text-white' : 'bg-gray-200 hover:bg-gray-300'}`}
            onClick={() => setTimeRange(3600)}
          >
            Last Hour
          </button>
          <button
            className={`px-4 py-2 rounded-md ${timeRange === 3600 * 6 ? 'bg-blue-600 text-white' : 'bg-gray-200 hover:bg-gray-300'}`}
            onClick={() => setTimeRange(3600 * 6)}
          >
            Last 6 Hours
          </button>
          <button
            className={`px-4 py-2 rounded-md ${timeRange === 3600 * 24 ? 'bg-blue-600 text-white' : 'bg-gray-200 hover:bg-gray-300'}`}
            onClick={() => setTimeRange(3600 * 24)}
          >
            Last 24 Hours
          </button>
        </div>
        
        <div className="flex gap-2">
          <input
            type="text"
            placeholder="Filter logs..."
            className="px-4 py-2 border rounded-md w-64"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
          <select 
            className="px-4 py-2 border rounded-md bg-white"
            value={selectedSeverity || ''}
            onChange={(e) => setSelectedSeverity(e.target.value || null)}
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>
      
      {/* Severity distribution */}
      <div className="bg-white rounded-lg shadow mb-6 p-4">
        <div className="text-sm font-medium mb-2">Severity Distribution</div>
        <div className="h-2 w-full flex rounded-full overflow-hidden">
          {severityCounts.critical && (
            <div 
              className="bg-red-500" 
              style={{ width: `${(severityCounts.critical / processedLogs.length) * 100}%` }}
              title={`Critical: ${severityCounts.critical}`} 
            />
          )}
          {severityCounts.high && (
            <div 
              className="bg-orange-500" 
              style={{ width: `${(severityCounts.high / processedLogs.length) * 100}%` }}
              title={`High: ${severityCounts.high}`} 
            />
          )}
          {severityCounts.medium && (
            <div 
              className="bg-yellow-500" 
              style={{ width: `${(severityCounts.medium / processedLogs.length) * 100}%` }}
              title={`Medium: ${severityCounts.medium}`} 
            />
          )}
          {severityCounts.low && (
            <div 
              className="bg-green-500" 
              style={{ width: `${(severityCounts.low / processedLogs.length) * 100}%` }}
              title={`Low: ${severityCounts.low}`} 
            />
          )}
        </div>
        <div className="flex justify-between mt-2 text-xs text-gray-500">
          <div className="flex items-center">
            <div className="w-3 h-3 rounded-full bg-red-500 mr-1"></div>
            <span>Critical: {severityCounts.critical || 0}</span>
          </div>
          <div className="flex items-center">
            <div className="w-3 h-3 rounded-full bg-orange-500 mr-1"></div>
            <span>High: {severityCounts.high || 0}</span>
          </div>
          <div className="flex items-center">
            <div className="w-3 h-3 rounded-full bg-yellow-500 mr-1"></div>
            <span>Medium: {severityCounts.medium || 0}</span>
          </div>
          <div className="flex items-center">
            <div className="w-3 h-3 rounded-full bg-green-500 mr-1"></div>
            <span>Low: {severityCounts.low || 0}</span>
          </div>
        </div>
      </div>
      
      {/* Logs Table */}
      <div className="bg-white rounded-lg shadow overflow-hidden">
        <div className="grid grid-cols-12 p-4 font-medium border-b bg-gray-50 text-gray-700">
          <div 
            className="col-span-2 cursor-pointer flex items-center" 
            onClick={() => handleSort('timestamp')}
          >
            Timestamp
            {sortField === 'timestamp' && (
              <span className="ml-1">{sortDirection === 'asc' ? '↑' : '↓'}</span>
            )}
          </div>
          <div 
            className="col-span-2 cursor-pointer flex items-center" 
            onClick={() => handleSort('source')}
          >
            Source
            {sortField === 'source' && (
              <span className="ml-1">{sortDirection === 'asc' ? '↑' : '↓'}</span>
            )}
          </div>
          <div className="col-span-1">Type</div>
          <div 
            className="col-span-1 cursor-pointer flex items-center" 
            onClick={() => handleSort('severity')}
          >
            Severity
            {sortField === 'severity' && (
              <span className="ml-1">{sortDirection === 'asc' ? '↑' : '↓'}</span>
            )}
          </div>
          <div className="col-span-6">Content</div>
        </div>
        
        {processedLogs.length === 0 ? (
          <div className="p-8 text-center text-gray-500">No logs found matching your criteria</div>
        ) : (
          <div className="max-h-96 overflow-y-auto">
            {processedLogs.map((log, index) => (
              <div
                key={index}
                className="grid grid-cols-12 p-4 hover:bg-gray-50 border-b"
              >
                <div className="col-span-2 text-gray-600 text-sm">
                  {new Date(log.timestamp).toLocaleString()}
                </div>
                <div className="col-span-2 font-medium text-gray-700">{log.source}</div>
                <div className="col-span-1 text-gray-700">{log.type}</div>
                <div className="col-span-1">
                  <span className={`px-2 py-1 rounded-full text-xs ${getSeverityClass(log.severity)}`}>
                    {log.severity || 'info'}
                  </span>
                </div>
                <div className="col-span-6 font-mono text-sm break-words text-gray-800">{log.content}</div>
              </div>
            ))}
          </div>
        )}
      </div>
      
      {/* Pagination placeholder - can be expanded with actual pagination if needed */}
      <div className="mt-4 flex justify-between items-center">
        <div className="text-sm text-gray-500">
          Showing {processedLogs.length} of {logs.length} logs
        </div>
        <div className="flex gap-2">
          <button className="px-4 py-2 bg-gray-200 rounded-md text-gray-700 hover:bg-gray-300">Previous</button>
          <button className="px-4 py-2 bg-gray-200 rounded-md text-gray-700 hover:bg-gray-300">Next</button>
        </div>
      </div>
    </div>
  );
};

export default SystemLogs;