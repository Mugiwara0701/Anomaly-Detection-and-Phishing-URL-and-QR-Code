import React, { useState, useEffect } from 'react';
import {
  LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid, ResponsiveContainer,
  ReferenceLine, BarChart, Bar, Legend, Cell
} from 'recharts';
import throttle from 'lodash.throttle';

const API_BASE_URL = "http://localhost:8001";
const WS_BASE_URL = "ws://localhost:8001";

const loadClientId = async () => {
  const maxRetries = 3;
  let attempt = 0;
  while (attempt < maxRetries) {
    try {
      const response = await fetch(`${API_BASE_URL}/get-client-id`, { timeout: 20000 });
      if (response.ok) {
        const clientId = await response.text();
        localStorage.setItem("network_monitor_client_id", clientId);
        console.log("Fetched client ID:", clientId);
        return clientId;
      }
    } catch (e) {
      console.warn(`Failed to fetch client ID (attempt ${attempt + 1}/${maxRetries}):`, e);
      attempt++;
      if (attempt < maxRetries) {
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }
  }
  return localStorage.getItem("network_monitor_client_id") || `client_${Math.random().toString(36).substring(2, 9)}`;
};

const CLIENT_ID = await loadClientId();
localStorage.setItem("network_monitor_client_id", CLIENT_ID);

class ErrorBoundary extends React.Component {
  state = { hasError: false, error: null };

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error("Error caught by boundary:", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex items-center justify-center min-h-screen" style={{ background: 'linear-gradient(135deg, #1e1e2f 0%, #27293d 100%)' }}>
          <div className="bg-white p-8 rounded-lg shadow-lg max-w-md w-full">
            <h2 className="text-2xl font-bold" style={{ color: 'rgb(160,32,240)' }}>Something Went Wrong</h2>
            <p className="text-gray-600 mt-2">An error occurred while rendering the Network Monitor. Please try refreshing the page or check the console for details.</p>
            <button
              onClick={() => window.location.reload()}
              className="mt-4 py-2 px-4 rounded-lg text-white"
              style={{ backgroundColor: 'rgb(160,32,240)', ':hover': { backgroundColor: 'rgb(140,28,210)' } }}
            >
              Refresh
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

function NIDS() {
  const [networkData, setNetworkData] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [showPopup, setShowPopup] = useState(false);
  const [currentAlert, setCurrentAlert] = useState(null);
  const [activeClientId, setActiveClientId] = useState(CLIENT_ID);
  const [modelStatus, setModelStatus] = useState({
    training: false,
    trained: false,
    samplesCollected: 0,
  });
  const [baseline, setBaseline] = useState({
    downloadSpeed: null,
    uploadSpeed: null,
    latency: null,
    packetsReceived: null,
  });
  const [permissionStatus, setPermissionStatus] = useState("none");
  const [lastNetworkStats, setLastNetworkStats] = useState({
    latency: 0,
    downloadSpeed: 0,
    uploadSpeed: 0,
    packetsReceived: 0,
    cpu: 0,
    memory: 0,
  });
  const [agentStatus, setAgentStatus] = useState("unknown");
  const [wsConnected, setWsConnected] = useState(false);
  const [attackStatus, setAttackStatus] = useState("stopped");
  const [attackDetails, setAttackDetails] = useState({ intensity: null, startTime: null, attackType: null });
  const [preventionEnabled, setPreventionEnabled] = useState(false);
  const [blockedIPs, setBlockedIPs] = useState([]);
  const [errorMessage, setErrorMessage] = useState(null);
  const [diagnosticInfo, setDiagnosticInfo] = useState({
    websocket_connection: false,
    data_received: false,
    rendering: false,
    last_error: null,
    last_message: null,
    message_count: 0
  });
  const [showDiagnostics, setShowDiagnostics] = useState(false);
  const [selectedAttackType, setSelectedAttackType] = useState('ddos');

  const throttledSetNetworkData = throttle(setNetworkData, 1000);

  const checkFrontendHealth = async () => {
    const health = {
      websocket_connection: wsConnected,
      data_received: networkData.length > 0,
      rendering: networkData.length > 0 && !errorMessage,
      last_error: errorMessage,
      last_message: diagnosticInfo.last_message,
      message_count: diagnosticInfo.message_count
    };
    setDiagnosticInfo(health);
    console.log('Frontend health check:', health);
    return health;
  };

  const requestPermission = async () => {
    setPermissionStatus("requested");
    try {
      const response = await fetch(`${API_BASE_URL}/status`, {
        method: "GET",
        headers: { "Content-Type": "application/json" },
      });
      if (response.ok) {
        setPermissionStatus("granted");
      } else {
        setPermissionStatus("agent_required");
      }
    } catch (error) {
      console.error("Error checking server status:", error);
      setPermissionStatus("agent_required");
    }
  };

  const connectWebSocket = (retryCount = 0) => {
    if (!activeClientId) {
      console.warn("No active client ID, aborting WebSocket connection");
      return;
    }
  
    const ws = new WebSocket(`${WS_BASE_URL}/ws`);
    
    const sendRegistration = () => {
      if (ws.readyState === WebSocket.OPEN && activeClientId) {
        ws.send(JSON.stringify({ 
          type: "register", 
          client_id: activeClientId 
        }));
      }
    };
  
    ws.onopen = () => {
      console.log(`✅ WebSocket Connected for client ${activeClientId}`);
      sendRegistration();
      setWsConnected(true);
      setDiagnosticInfo(prev => ({ ...prev, websocket_connection: true }));
      ws.send(JSON.stringify({ type: "register", client_id: activeClientId }));
      const heartbeat = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: "heartbeat", client_id: activeClientId }));
        }
      }, 30000);
      ws.onclose = () => {
        clearInterval(heartbeat);
        setWsConnected(false);
        setDiagnosticInfo(prev => ({ ...prev, websocket_connection: false, last_error: 'WebSocket disconnected' }));
        console.warn("⚠ WebSocket Disconnected. Reconnecting...");
        if (retryCount < 5) {
          setTimeout(() => connectWebSocket(retryCount + 1), 3000 * (2 ** retryCount));
        } else {
          setErrorMessage("Failed to reconnect to WebSocket after multiple attempts");
          setDiagnosticInfo(prev => ({ ...prev, last_error: 'WebSocket reconnection failed' }));
        }
      };
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        console.log("WebSocket message received:", data);
        setDiagnosticInfo(prev => ({
          ...prev,
          last_message: data,
          message_count: prev.message_count + 1,
          data_received: true
        }));
        if (data.type === "data_update") {
          console.log("Received data_update:", data.data);
          updateNetworkStats(data.data);
          setModelStatus((prev) => ({
            ...prev,
            samplesCollected: prev.samplesCollected + 1,
          }));
        }
        
        if (data.alert) {
          const alertData = {
            message: data.alert.message,
            details: data.alert.details || {},
            anomalyScore: Math.abs(data.alert.details.score) || 0,
            anomalousFeatures: data.alert.details.features || [],
            timestamp: new Date(data.alert.timestamp).toLocaleTimeString(),
            sourceIp: data.alert.source_ip || "unknown",
            isSystem: false,
            confidencePercent: data.alert.details.confidence_percent || 0
          };
          setAlerts((prev) => [...prev, alertData].slice(-5));
          setCurrentAlert(alertData);
          setShowPopup(true);
          setTimeout(() => setShowPopup(false), 8000);
        }
        if (data.type === "client_id") {
          console.log(`Received client_id: ${data.client_id}, activeClientId: ${activeClientId}`);
          setActiveClientId(data.client_id);
        }
        if (data.type === "baseline_update") {
          setBaseline(data.baseline);
          console.log("Updated baseline:", data.baseline);
      }
        if (data.type === "model_status") {
          setModelStatus({
            training: data.status === "training" || data.status === "training_started",
            trained: data.status === "trained" || data.status === "training_completed",
            samplesCollected: data.samples_collected || modelStatus.samplesCollected,
          });
          if (data.status === "training_completed") {
            const fetchBaseline = async () => {
                const response = await fetch(`${API_BASE_URL}/data`);
                const baselineData = await response.json();
                setBaseline(baselineData[activeClientId]?.baseline || {});
            };
            fetchBaseline();
        }
          if (data.status === "training_started") {
            setCurrentAlert({
              message: "Model training started",
              isSystem: true,
              timestamp: new Date().toLocaleTimeString(),
            });
            setShowPopup(true);
            setTimeout(() => setShowPopup(false), 3000);
          } else if (data.status === "training_completed") {
            setCurrentAlert({
              message: "Model training completed successfully",
              isSystem: true,
              timestamp: new Date().toLocaleTimeString(),
            });
            setShowPopup(true);
            setTimeout(() => setShowPopup(false), 3000);
          } else if (data.status === "training_error") {
            setErrorMessage(`Model training failed: ${data.error}`);
            setCurrentAlert({
              message: `Model training failed: ${data.error}`,
              isSystem: true,
              timestamp: new Date().toLocaleTimeString(),
            });
            setShowPopup(true);
            setTimeout(() => setShowPopup(false), 5000);
          }
        }
        if (data.type === "attack_status") {
          setAttackStatus(data.status);
          setAttackDetails({
            intensity: data.intensity || null,
            startTime: data.status === "started" ? new Date() : null,
            attackType: data.attack_type || null,
          });
          console.log(`Attack status updated to ${data.status}, type: ${data.attack_type}`);
        }
        if (data.type === "prevention_status") {
          setPreventionEnabled(data.status);
        }
        if (data.type === "blocked_ip") {
          setBlockedIPs((prev) => [...prev, data.ip]);
        }
        if (data.type === "unblocked_ip") {
          setBlockedIPs((prev) => prev.filter((ip) => ip !== data.ip));
        }
      } catch (error) {
        console.error("❌ Error processing WebSocket message:", error);
        setDiagnosticInfo(prev => ({ ...prev, last_error: `WebSocket message error: ${error.message}` }));
      }
    };

    ws.onerror = (error) => {
      console.error("❌ WebSocket error:", error);
      setWsConnected(false);
      setDiagnosticInfo(prev => ({ ...prev, websocket_connection: false, last_error: `WebSocket error: ${error.message}` }));
    };
    return ws;
  };

  useEffect(() => {
    const storedClientId = localStorage.getItem("network_monitor_client_id");
    if (storedClientId) setActiveClientId(storedClientId);
  }, []);

  useEffect(() => {
    const loadAndSetClientId = async () => {
      const storedClientId = localStorage.getItem("network_monitor_client_id");
      if (!storedClientId) {
        const newClientId = await loadClientId();
        setActiveClientId(newClientId);
      } else {
        setActiveClientId(storedClientId);
      }
    };
    loadAndSetClientId();
  }, []);

  useEffect(() => {
    let ws = null;
    if (activeClientId && permissionStatus === "granted") {
      ws = connectWebSocket();
      fetchInitialData();
    }
    return () => ws && ws.close();
  }, [activeClientId, permissionStatus]);

  useEffect(() => {
    let ws = null;
    if (permissionStatus === "granted") {
      ws = connectWebSocket();
      fetchInitialData();
    }
    return () => ws && ws.close();
  }, [permissionStatus]);

  useEffect(() => {
    checkFrontendHealth();
    const interval = setInterval(checkFrontendHealth, 30000);
    return () => clearInterval(interval);
  }, [wsConnected, networkData, errorMessage]);

  const fetchInitialData = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/data`);
      if (response.ok) {
        const data = await response.json();
        console.log("Initial data fetched:", data);
        if (data[activeClientId] && data[activeClientId].network_history && data[activeClientId].network_history.length > 0) {
          setNetworkData(
            data[activeClientId].network_history.map((item) => ({
              time: new Date(item.timestamp).toLocaleTimeString(),
              downloadSpeed: item.download || 0,
              uploadSpeed: item.upload || 0,
              latency: item.latency || 0,
              packetsReceived: item.packets_received || 0,
              cpu: item.cpu || 0,
              memory: item.memory || 0,
            }))
          );
          setDiagnosticInfo(prev => ({ ...prev, data_received: true, rendering: true }));
        }
        if (data[activeClientId] && data[activeClientId].alerts && data[activeClientId].alerts.length > 0) {
          setAlerts(
            data[activeClientId].alerts.slice(-5).map((alert) => ({
              message: alert.message,
              details: alert.details || {},
              anomalyScore: Math.abs(alert.details.score) || 0,
              anomalousFeatures: alert.details.features || [],
              timestamp: new Date(alert.timestamp).toLocaleTimeString(),
              sourceIp: alert.source_ip || "unknown",
              isSystem: false,
              confidencePercent: data.alert.details?.confidence_percent || 0
            }))
          );
        }
        if (data[activeClientId] && data[activeClientId].baseline) setBaseline(data[activeClientId].baseline);
        if (data[activeClientId] && data[activeClientId].model_status) {
          setModelStatus({
            training: data[activeClientId].model_status.training || false,
            trained: data[activeClientId].model_status.trained || false,
            samplesCollected: data[activeClientId].model_status.samples_collected || 0,
          });
        }
        if (data[activeClientId] && data[activeClientId].current_stats) setLastNetworkStats(data[activeClientId].current_stats);
        if (data[activeClientId] && data[activeClientId].blocked_ips) setBlockedIPs(data[activeClientId].blocked_ips);
      } else {
        console.error("Initial data fetch failed");
        setDiagnosticInfo(prev => ({ ...prev, last_error: `Initial data fetch failed with status ${response.status}` }));
      }
    } catch (error) {
      console.error("Error fetching initial data:", error);
      setDiagnosticInfo(prev => ({ ...prev, last_error: `Initial data fetch error: ${error.message}` }));
    }
  };

  const updateNetworkStats = (data) => {
    throttledSetNetworkData((prev) => {
      const newEntry = {
        time: new Date(data.timestamp).toLocaleTimeString(),
        downloadSpeed: data.download || 0,
        uploadSpeed: data.upload || 0,
        latency: data.latency || 0,
        packetsReceived: data.packets_received || 0,
        cpu: data.cpu || 0,
        memory: data.memory || 0,
      };
      console.log("Adding new entry:", newEntry);
      setDiagnosticInfo(prev => ({ ...prev, data_received: true, rendering: true }));
      return [...prev, newEntry].slice(-50);
    });
    setLastNetworkStats({
      latency: data.latency || 0,
      downloadSpeed: data.download || 0,
      uploadSpeed: data.upload || 0,
      packetsReceived: data.packets_received || 0,
      cpu: data.cpu || 0,
      memory: data.memory || 0,
    });
  };

  const handleRetrain = async () => {
    if (!activeClientId) {
      setCurrentAlert({
        message: "No active client ID. Please reconnect or refresh.",
        isSystem: true,
        timestamp: new Date().toLocaleTimeString(),
      });
      setShowPopup(true);
      setTimeout(() => setShowPopup(false), 3000);
      return;
    }
    try {
      const response = await fetch(`${API_BASE_URL}/train-model/${activeClientId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });
      if (!response.ok) throw new Error("Training failed");
      setCurrentAlert({
        message: "Model retraining started successfully!",
        isSystem: true,
        timestamp: new Date().toLocaleTimeString(),
      });
      setShowPopup(true);
    } catch (error) {
      console.error("Retrain error:", error);
      setCurrentAlert({
        message: `Failed to start retraining: ${error.message}. Check server connection.`,
        isSystem: true,
        timestamp: new Date().toLocaleTimeString(),
      });
      setShowPopup(true);
    } finally {
      setTimeout(() => setShowPopup(false), 3000);
    }
  };

  const handleSimulateAttack = async () => {
    if (!activeClientId || !wsConnected) {
      setCurrentAlert({
        message: "No active client ID or WebSocket disconnected. Please reconnect or refresh.",
        isSystem: true,
        timestamp: new Date().toLocaleTimeString(),
      });
      setShowPopup(true);
      setTimeout(() => setShowPopup(false), 3000);
      return;
    }
    try {
      const endpoint = attackStatus === "stopped" 
      ? `simulate-attack/${activeClientId}` 
      : `stop-attack/${activeClientId}`;
      
      const response = await fetch(`${API_BASE_URL}/${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });
      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Server responded with ${response.status}: ${errorText}`);
      }
      if (response.ok) {
        setAttackStatus(attackStatus === "stopped" ? "started" : "stopped");
        setCurrentAlert({
          message: attackStatus === "stopped" ? `Simulated ${selectedAttackType} attack started` : "Attack simulation stopped",
          isSystem: true,
          timestamp: new Date().toLocaleTimeString(),
        });
        setShowPopup(true);
        setTimeout(() => setShowPopup(false), 3000);
      } else if (response.status === 404) {
        setCurrentAlert({
          message: "Client not found. Please reconnect or refresh.",
          isSystem: true,
          timestamp: new Date().toLocaleTimeString(),
        });
        setShowPopup(true);
        setTimeout(() => setShowPopup(false), 3000);
      } else {
        throw new Error(`Server responded with ${response.status}: ${await response.text()}`);
      }
    } catch (error) {
      console.error("Attack simulation error:", error);
      setCurrentAlert({
        message: `Failed to ${attackStatus === "stopped" ? "start" : "stop"} attack: ${error.message}.`,
        isSystem: true,
        timestamp: new Date().toLocaleTimeString(),
      });
      setShowPopup(true);
      setTimeout(() => setShowPopup(false), 3000);
    }
  };

  const handleTogglePrevention = async () => {
    if (!activeClientId) {
      setCurrentAlert({
        message: "No active client ID. Please reconnect or refresh.",
        isSystem: true,
        timestamp: new Date().toLocaleTimeString(),
      });
      setShowPopup(true);
      setTimeout(() => setShowPopup(false), 3000);
      return;
    }
    try {
      const response = await fetch(`${API_BASE_URL}/toggle-prevention/${activeClientId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prevention: !preventionEnabled }),
      });
      if (response.ok) {
        setPreventionEnabled(!preventionEnabled);
        setCurrentAlert({
          message: `Prevention mode ${!preventionEnabled ? "enabled" : "disabled"}`,
          isSystem: true,
          timestamp: new Date().toLocaleTimeString(),
        });
        setShowPopup(true);
        setTimeout(() => setShowPopup(false), 3000);
      } else {
        throw new Error("Failed to toggle prevention");
      }
    } catch (error) {
      console.error("Prevention toggle error:", error);
      setCurrentAlert({
        message: `Failed to toggle prevention: ${error.message}`,
        isSystem: true,
        timestamp: new Date().toLocaleTimeString(),
      });
      setShowPopup(true);
      setTimeout(() => setShowPopup(false), 3000);
    }
  };

  const handleUnblockIP = async (ip) => {
    try {
      const response = await fetch(`${API_BASE_URL}/unblock-ip/${ip}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });
      if (response.ok) {
        setBlockedIPs((prev) => prev.filter((blockedIp) => ip !== blockedIp));
        setCurrentAlert({
          message: `IP ${ip} unblocked`,
          isSystem: true,
          timestamp: new Date().toLocaleTimeString(),
        });
        setShowPopup(true);
        setTimeout(() => setShowPopup(false), 3000);
      } else {
        throw new Error("Failed to unblock IP");
      }
    } catch (error) {
      console.error("Unblock IP error:", error);
      setCurrentAlert({
        message: `Failed to unblock IP: ${error.message}`,
        isSystem: true,
        timestamp: new Date().toLocaleTimeString(),
      });
      setShowPopup(true);
      setTimeout(() => setShowPopup(false), 3000);
    }
  };

  const getPercentChange = (current, baseline) => {
    if (!baseline || baseline === 0) return "N/A";
    const change = ((current - baseline) / baseline) * 100;
    return `${change > 0 ? "+" : ""}${change.toFixed(1)}%`;
  };

  const getPacketBarColor = (value, baseline) => {
    if (!baseline) return "#8B5CF6";
    if (value > baseline * 1.5) return "#EF4444";
    if (value < baseline * 0.5) return "#FBBF24";
    return "#8B5CF6";
  };

  if (permissionStatus === "agent_required") {
    return (
      <div className="flex items-center justify-center min-h-screen" style={{ background: 'linear-gradient(135deg, #1e1e2f 0%, #27293d 100%)' }}>
        <div className="bg-white p-8 rounded-lg shadow-lg max-w-md w-full">
          <h2 className="text-2xl font-bold" style={{ color: 'rgb(160,32,240)' }}>Agent Required</h2>
          <p className="text-gray-600 mt-2">
            The Network Monitor requires the server and capture agent to be running.
          </p>
          <div className="bg-yellow-50 p-4 rounded-lg mb-6">
            <h3 className="font-semibold mb-2" style={{ color: 'rgb(160,32,240)' }}>Setup Instructions:</h3>
            <ol className="list-decimal pl-5 text-gray-700 space-y-2">
              <li>Ensure Python is installed</li>
              <li>Run: <code className="bg-gray-200 px-2 py-1 rounded">python app.py</code></li>
              <li>Run: <code className="bg-gray-200 px-2 py-1 rounded">python capture.py</code></li>
            </ol>
          </div>
          <div className="flex justify-between">
            <button
              onClick={() => setPermissionStatus("none")}
              className="py-3 px-4 rounded-lg text-white"
              style={{ backgroundColor: 'rgb(160,32,240)', ':hover': { backgroundColor: 'rgb(140,28,210)' } }}
            >
              Back
            </button>
            <button
              onClick={() => setPermissionStatus("granted")}
              className="py-3 px-4 rounded-lg text-white"
              style={{ backgroundColor: 'rgb(160,32,240)', ':hover': { backgroundColor: 'rgb(140,28,210)' } }}
            >
              I've Started the Server & Agent
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (permissionStatus !== "granted") {
    return (
      <div className="flex items-center justify-center min-h-screen" style={{ background: 'linear-gradient(135deg, #1e1e2f 0%, #27293d 100%)' }}>
        <div className="bg-white p-8 rounded-lg shadow-lg max-w-md w-full">
          <h2 className="text-2xl font-bold" style={{ color: 'rgb(160,32,240)' }}>Network Monitor</h2>
          <p className="text-gray-600 mt-2">
            This application monitors network traffic and detects anomalies.
          </p>
          <div className="bg-blue-50 p-4 rounded-lg mb-6">
            <h3 className="font-semibold mb-2" style={{ color: 'rgb(160,32,240)' }}>We'll collect:</h3>
            <ul className="list-disc pl-5 text-gray-700 space-y-1">
              <li>Download and upload speeds</li>
              <li>Network latency</li>
              <li>Packet information</li>
            </ul>
          </div>
          <button
            onClick={requestPermission}
            className={`w-full py-3 rounded-lg text-white font-medium ${
              permissionStatus === "requested" ? "bg-gray-400 cursor-wait" : ""
            }`}
            style={permissionStatus !== "requested" ? { backgroundColor: 'rgb(160,32,240)', ':hover': { backgroundColor: 'rgb(140,28,210)' } } : {}}
            disabled={permissionStatus === "requested"}
          >
            {permissionStatus === "requested"
              ? "Checking Server Status..."
              : "Connect to Network Monitor"}
          </button>
        </div>
      </div>
    );
  }

  return (
    <ErrorBoundary>
      <div className="flex min-h-screen" style={{ background: 'linear-gradient(135deg, #1e1e2f 0%, #27293d 100%)' }}>
        <div className="flex-1 p-6 overflow-y-auto max-h-screen scrollbar-thin scrollbar-thumb-gray-400 scrollbar-track-gray-100">
          <header className="mb-8">
            <h2 className="text-3xl font-bold text-center mb-2" style={{ color: 'rgb(160,32,240)' }}>
              📊 Network Performance Monitor
            </h2>
            <div className="flex justify-center items-center gap-4 flex-wrap">
              <div
                className={`px-3 py-1 rounded-full text-white text-sm font-medium ${
                  modelStatus.training
                    ? "bg-yellow-500"
                    : modelStatus.trained
                    ? "bg-green-500"
                    : "bg-red-500"
                }`}
              >
                {modelStatus.training
                  ? "🧠 Training ML Model..."
                  : modelStatus.trained
                  ? "✅ ML Model Active"
                  : "❌ ML Model Inactive"}
              </div>
              <div className="text-sm bg-blue-100 text-blue-800 px-3 py-1 rounded-full">
                Client ID: {activeClientId.substring(0, 8)}...
              </div>
              <div
                className={`text-sm px-3 py-1 rounded-full ${
                  wsConnected
                    ? "bg-green-100 text-green-800"
                    : "bg-red-100 text-red-800"
                }`}
              >
                {wsConnected ? "🟢 Connected" : "🔴 Disconnected"}
              </div>
              {modelStatus.samplesCollected > 0 && (
                <div className="text-sm text-gray-400">
                  {modelStatus.samplesCollected} samples collected
                </div>
              )}
              <button
              disabled
                className="px-4 py-1 rounded-lg text-white text-sm transition-colors"
                onClick={handleRetrain}
                style={{ backgroundColor: 'rgb(204,204,204)', ':hover': { backgroundColor: 'rgb(140,28,210)' } }}
              >
                Retrain Model
              </button>
              <button
                className="px-4 py-1 rounded-lg text-white text-sm transition-colors"
                onClick={() => setShowDiagnostics(!showDiagnostics)}
                style={{ backgroundColor: 'rgb(160,32,240)', ':hover': { backgroundColor: 'rgb(140,28,210)' } }}
              >
                {showDiagnostics ? 'Hide Diagnostics' : 'Show Diagnostics'}
              </button>
            </div>
          </header>

          {showDiagnostics && (
            <div className="bg-white p-4 rounded-lg shadow-md mt-4">
              <h3 className="text-lg font-semibold mb-2" style={{ color: 'rgb(160,32,240)' }}>Frontend Diagnostics</h3>
              <ul className="text-sm text-gray-600 space-y-2">
                <li>WebSocket Connection: {diagnosticInfo.websocket_connection ? '✅ Connected' : '❌ Disconnected'}</li>
                <li>Data Received: {diagnosticInfo.data_received ? '✅ Yes' : '❌ No'}</li>
                <li>Rendering: {diagnosticInfo.rendering ? '✅ Yes' : '❌ No'}</li>
                <li>Message Count: {diagnosticInfo.message_count}</li>
                <li>Last Error: {diagnosticInfo.last_error || 'None'}</li>
                <li>Last Message: {JSON.stringify(diagnosticInfo.last_message) || 'None'}</li>
              </ul>
            </div>
          )}

          {modelStatus.trained && (
            <div className="mb-6 bg-white p-4 rounded-lg shadow-md">
              <h3 className="text-lg font-semibold mb-2" style={{ color: 'rgb(160,32,240)' }}>
                🔍 Your Network Baseline
              </h3>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-blue-50 p-3 rounded">
                  <div className="text-xs text-gray-500">Download Speed</div>
                  <div className="font-semibold">
                    {baseline.downloadSpeed?.toFixed(2)} KB/s
                  </div>
                </div>
                <div className="bg-green-50 p-3 rounded">
                  <div className="text-xs text-gray-500">Upload Speed</div>
                  <div className="font-semibold">
                    {baseline.uploadSpeed?.toFixed(2)} KB/s
                  </div>
                </div>
                <div className="bg-red-50 p-3 rounded">
                  <div className="text-xs text-gray-500">Latency</div>
                  <div className="font-semibold">
                    {baseline.latency?.toFixed(0)} ms
                  </div>
                </div>
                <div className="bg-purple-50 p-3 rounded">
                  <div className="text-xs text-gray-500">Packets</div>
                  <div className="font-semibold">
                    {baseline.packetsReceived?.toFixed(0)}
                  </div>
                </div>
              </div>
            </div>
          )}

          {showPopup && currentAlert && (
            <div className="fixed inset-0 flex justify-center items-center bg-black bg-opacity-50 z-50">
              <div
                className={`bg-white p-6 rounded-lg shadow-lg w-96 ${
                  currentAlert.isSystem
                    ? "border-l-4 border-blue-500"
                    : "border-l-4 border-red-500"
                }`}
              >
                <div className="flex justify-between items-center mb-4">
                  <h3
                    className="text-xl font-semibold"
                    style={{ color: 'rgb(160,32,240)' }}
                  >
                    {currentAlert.isSystem
                      ? "🧠 System Notification"
                      : "⚠ Suspicious Activity Detected"}
                  </h3>
                  <span className="text-sm text-gray-500">
                    {currentAlert.timestamp}
                  </span>
                </div>
                <p className="text-gray-700 mb-4">{currentAlert.message}</p>
                {!currentAlert.isSystem && (
                  <>
                    <div className="mb-4">
                      <div className="text-sm mb-1">
                        Source IP: {currentAlert.sourceIp}
                      </div>
                      <div className="flex justify-between text-sm mb-1">
                        <span>Anomaly Confidence:</span>
                        <span className="font-medium">
                          {currentAlert.confidencePercent.toFixed(1)}%
                        </span>
                      </div>
                      <div className="w-full bg-gray-200 rounded-full h-2.5">
                        <div
                          className="bg-red-600 h-2.5 rounded-full"
                          style={{ width: `${currentAlert.confidencePercent}%` }}
                        ></div>
                      </div>
                    </div>
                    <div className="bg-gray-50 p-3 rounded">
                      <h4 className="text-sm font-semibold mb-2" style={{ color: 'rgb(160,32,240)' }}>
                        Current Metrics:
                      </h4>
                      <div className="text-sm text-gray-600 grid grid-cols-2 gap-2">
                        <p>Download: {lastNetworkStats.downloadSpeed?.toFixed(2)} KB/s</p>
                        <p>Upload: {lastNetworkStats.uploadSpeed?.toFixed(2)} KB/s</p>
                        <p>Latency: {lastNetworkStats.latency?.toFixed(0)} ms</p>
                        <p>Packets: {lastNetworkStats.packetsReceived}</p>
                        <p>CPU: {lastNetworkStats.cpu?.toFixed(1)}%</p>
                        <p>Memory: {lastNetworkStats.memory?.toFixed(1)}%</p>
                      </div>
                    </div>
                  </>
                )}
                <button
                  className="mt-4 w-full py-2 rounded text-white transition-colors"
                  onClick={() => setShowPopup(false)}
                  style={{ backgroundColor: 'rgb(160,32,240)', ':hover': { backgroundColor: 'rgb(140,28,210)' } }}
                >
                  Dismiss
                </button>
              </div>
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
            <div className="bg-white p-4 rounded-lg shadow-md">
              <h3 className="text-lg font-semibold mb-4" style={{ color: 'rgb(160,32,240)' }}>
                Download & Upload Speed
              </h3>
              <div className="h-80 overflow-y-auto">
                <ResponsiveContainer width="100%" height={300}>
                  {networkData.length > 0 ? (
                    <LineChart data={networkData}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis
                        dataKey="time"
                        tick={{ fontSize: 12 }}
                        interval="preserveStartEnd"
                        minTickGap={40}
                      />
                      <YAxis
                        label={{ value: "KB/s", angle: -90, position: "insideLeft" }}
                        tick={{ fontSize: 12 }}
                      />
                      <Tooltip formatter={(value) => [`${value.toFixed(2)} KB/s`]} />
                      <Line
                        type="monotone"
                        dataKey="downloadSpeed"
                        stroke="#3B82F6"
                        strokeWidth={2}
                        dot={false}
                        name="Download"
                      />
                      <Line
                        type="monotone"
                        dataKey="uploadSpeed"
                        stroke="#10B981"
                        strokeWidth={2}
                        dot={false}
                        name="Upload"
                      />
                      {baseline.downloadSpeed && (
                        <ReferenceLine
                          y={baseline.downloadSpeed}
                          stroke="#3B82F6"
                          strokeDasharray="3 3"
                          label={{
                            value: "Download Baseline",
                            position: "insideBottomRight",
                            fill: "#3B82F6",
                            fontSize: 10,
                          }}
                        />
                      )}
                      {baseline.uploadSpeed && (
                        <ReferenceLine
                          y={baseline.uploadSpeed}
                          stroke="#10B981"
                          strokeDasharray="3 3"
                          label={{
                            value: "Upload Baseline",
                            position: "insideTopRight",
                            fill: "#10B981",
                            fontSize: 10,
                          }}
                        />
                      )}
                      <Legend verticalAlign="bottom" height={30} />
                    </LineChart>
                  ) : (
                    <p className="text-center text-gray-500">No data available</p>
                  )}
                </ResponsiveContainer>
              </div>
            </div>

            <div className="bg-white p-4 rounded-lg shadow-md">
              <h3 className="text-lg font-semibold mb-4" style={{ color: 'rgb(160,32,240)' }}>Latency</h3>
              <div className="h-80 overflow-y-auto">
                <ResponsiveContainer width="100%" height={300}>
                  {networkData.length > 0 ? (
                    <LineChart data={networkData}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis
                        dataKey="time"
                        tick={{ fontSize: 12 }}
                        interval="preserveStartEnd"
                        minTickGap={40}
                      />
                      <YAxis
                        label={{ value: "ms", angle: -90, position: "insideLeft" }}
                        tick={{ fontSize: 12 }}
                      />
                      <Tooltip formatter={(value) => [`${value.toFixed(1)} ms`]} />
                      <Line
                        type="monotone"
                        dataKey="latency"
                        stroke="#EF4444"
                        strokeWidth={2}
                        dot={false}
                        name="Latency"
                      />
                      {baseline.latency && (
                        <ReferenceLine
                          y={baseline.latency}
                          stroke="#EF4444"
                          strokeDasharray="3 3"
                          label={{
                            value: "Latency Baseline",
                            position: "insideTopRight",
                            fill: "#EF4444",
                            fontSize: 10,
                          }}
                        />
                      )}
                    </LineChart>
                  ) : (
                    <p className="text-center text-gray-500">No data available</p>
                  )}
                </ResponsiveContainer>
              </div>
            </div>

            <div className="bg-white p-4 rounded-lg shadow-md">
              <h3 className="text-lg font-semibold mb-4" style={{ color: 'rgb(160,32,240)' }}>Packets Received</h3>
              <div className="h-80 overflow-y-auto">
                <ResponsiveContainer width="100%" height={300}>
                  {networkData.length > 0 ? (
                    <BarChart data={networkData.slice(-15)}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis
                        dataKey="time"
                        tick={{ fontSize: 12 }}
                        interval="preserveStartEnd"
                        minTickGap={40}
                      />
                      <YAxis tick={{ fontSize: 12 }} />
                      <Tooltip formatter={(value) => [`${value} packets`]} />
                      <Bar dataKey="packetsReceived" fill="#8B5CF6" name="Packets">
                        {networkData.slice(-15).map((entry, index) => (
                          <Cell
                            key={`cell-${index}`}
                            fill={getPacketBarColor(entry.packetsReceived, baseline.packetsReceived)}
                          />
                        ))}
                      </Bar>
                      {baseline.packetsReceived && (
                        <ReferenceLine
                          y={baseline.packetsReceived}
                          stroke="#8B5CF6"
                          strokeDasharray="3 3"
                          label={{
                            value: "Packets Baseline",
                            position: "insideTopRight",
                            fill: "#8B5CF6",
                            fontSize: 10,
                          }}
                        />
                      )}
                    </BarChart>
                  ) : (
                    <p className="text-center text-gray-500">No data available</p>
                  )}
                </ResponsiveContainer>
              </div>
            </div>

            <div className="bg-white p-4 rounded-lg shadow-md">
              <h3 className="text-lg font-semibold mb-4" style={{ color: 'rgb(160,32,240)' }}>Recent Alerts</h3>
              {alerts.length === 0 ? (
                <div className="bg-gray-50 p-4 rounded text-center">
                  <p className="text-gray-500">No alerts detected yet</p>
                  <p className="text-sm text-gray-400 mt-1">
                    Alerts will appear here when anomalies are detected
                  </p>
                </div>
              ) : (
                <div className="space-y-3 max-h-64 overflow-y-auto">
                  {alerts.map((alert, index) => (
                    <div
                      key={index}
                      className="bg-red-50 border-l-4 border-red-500 p-3 rounded-md"
                    >
                      <div className="flex justify-between items-start">
                        <h4 className="font-medium text-red-700">{alert.message}</h4>
                        <span className="text-xs text-gray-500">{alert.timestamp}</span>
                      </div>
                      <div className="mt-1">
                        <div className="flex items-center text-sm">
                          <span className="text-gray-600 mr-2">Confidence:</span>
                          <div className="w-24 bg-gray-200 rounded-full h-1.5 mr-2">
                            <div
                              className="bg-red-600 h-1.5 rounded-full"
                              style={{ width: `${alert.confidencePercent}%` }}
                            ></div>
                          </div>
                          <span className="text-xs font-medium">
                            {alert.confidencePercent.toFixed(1)}%
                          </span>
                        </div>
                        <div className="text-sm text-gray-600">
                          Source IP: {alert.sourceIp}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="bg-white p-4 rounded-lg shadow-md">
              <h3 className="text-lg font-semibold mb-4" style={{ color: 'rgb(160,32,240)' }}>CPU Usage</h3>
              <div className="h-80 overflow-y-auto">
                <ResponsiveContainer width="100%" height={300}>
                  {networkData.length > 0 ? (
                    <LineChart data={networkData}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="time" tick={{ fontSize: 12 }} />
                      <YAxis
                        label={{ value: "%", angle: -90, position: "insideLeft" }}
                      />
                      <Tooltip formatter={(value) => [`${value.toFixed(1)}%`]} />
                      <Line
                        dataKey="cpu"
                        stroke="#FF6384"
                        strokeWidth={2}
                        dot={false}
                        name="CPU Usage"
                      />
                    </LineChart>
                  ) : (
                    <p className="text-center text-gray-500">No data available</p>
                  )}
                </ResponsiveContainer>
              </div>
            </div>

            <div className="bg-white p-4 rounded-lg shadow-md">
              <h3 className="text-lg font-semibold mb-4" style={{ color: 'rgb(160,32,240)' }}>Memory Usage</h3>
              <div className="h-80 overflow-y-auto">
                <ResponsiveContainer width="100%" height={300}>
                  {networkData.length > 0 ? (
                    <LineChart data={networkData}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="time" tick={{ fontSize: 12 }} />
                      <YAxis
                        label={{ value: "%", angle: -90, position: "insideLeft" }}
                      />
                      <Tooltip formatter={(value) => [`${value.toFixed(1)}%`]} />
                      <Line
                        dataKey="memory"
                        stroke="#4BC0C0"
                        strokeWidth={2}
                        dot={false}
                        name="Memory Usage"
                      />
                    </LineChart>
                  ) : (
                    <p className="text-center text-gray-500">No data available</p>
                  )}
                </ResponsiveContainer>
              </div>
            </div>
          </div>

          <div className="bg-white p-6 rounded-lg shadow-md mb-8">
            <h3 className="text-lg font-semibold mb-4" style={{ color: 'rgb(160,32,240)' }}>Current Network Status</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
              <div className="bg-blue-50 p-4 rounded-lg">
                <div className="flex justify-between items-center mb-2">
                  <h4 className="text-blue-800 font-medium" style={{ color: 'rgb(160,32,240)' }}>Download</h4>
                  <span className="bg-blue-100 text-blue-600 text-xs px-2 py-1 rounded">Speed</span>
                </div>
                <div className="text-2xl font-bold text-blue-600">
                  {(lastNetworkStats.downloadSpeed ?? 0).toFixed(2)} <span className="text-sm ml-1 font-normal">KB/s</span>
                </div>
                {baseline.downloadSpeed && (
                  <div
                    className={`text-xs mt-1 ${
                      lastNetworkStats.downloadSpeed < baseline.downloadSpeed * 0.8
                        ? "text-red-500"
                        : lastNetworkStats.downloadSpeed > baseline.downloadSpeed * 1.2
                        ? "text-green-500"
                        : "text-gray-500"
                    }`}
                  >
                    {getPercentChange(lastNetworkStats.downloadSpeed, baseline.downloadSpeed)} from baseline
                  </div>
                )}
              </div>
              <div className="bg-green-50 p-4 rounded-lg">
                <div className="flex justify-between items-center mb-2">
                  <h4 className="text-green-800 font-medium" style={{ color: 'rgb(160,32,240)' }}>Upload</h4>
                  <span className="bg-green-100 text-green-600 text-xs px-2 py-1 rounded">Speed</span>
                </div>
                <div className="text-2xl font-bold text-green-600">
                  {(lastNetworkStats.uploadSpeed ?? 0).toFixed(2)} <span className="text-sm ml-1 font-normal">KB/s</span>
                </div>
                {baseline.uploadSpeed && (
                  <div
                    className={`text-xs mt-1 ${
                      lastNetworkStats.uploadSpeed < baseline.uploadSpeed * 0.8
                        ? "text-red-500"
                        : lastNetworkStats.uploadSpeed > baseline.uploadSpeed * 1.2
                        ? "text-green-500"
                        : "text-gray-500"
                    }`}
                  >
                    {getPercentChange(lastNetworkStats.uploadSpeed, baseline.uploadSpeed)} from baseline
                  </div>
                )}
              </div>
              <div className="bg-red-50 p-4 rounded-lg">
                <div className="flex justify-between items-center mb-2">
                  <h4 className="text-red-800 font-medium" style={{ color: 'rgb(160,32,240)' }}>Latency</h4>
                  <span className="bg-red-100 text-red-600 text-xs px-2 py-1 rounded">Response</span>
                </div>
                <div className="text-2xl font-bold text-red-600">
                  {(lastNetworkStats.latency ?? 0).toFixed(0)} <span className="text-sm ml-1 font-normal">ms</span>
                </div>
                {baseline.latency && (
                  <div
                    className={`text-xs mt-1 ${
                      lastNetworkStats.latency > baseline.latency * 1.2
                        ? "text-red-500"
                        : lastNetworkStats.latency < baseline.latency * 0.8
                        ? "text-green-500"
                        : "text-gray-500"
                    }`}
                  >
                    {getPercentChange(lastNetworkStats.latency, baseline.latency)} from baseline
                  </div>
                )}
              </div>
              <div className="bg-purple-50 p-4 rounded-lg">
                <div className="flex justify-between items-center mb-2">
                  <h4 className="text-purple-800 font-medium" style={{ color: 'rgb(160,32,240)' }}>Packets</h4>
                  <span className="bg-purple-100 text-purple-600 text-xs px-2 py-1 rounded">Received</span>
                </div>
                <div className="text-2xl font-bold text-purple-600">
                  {(lastNetworkStats.packetsReceived ?? 0).toFixed(0)}
                </div>
                {baseline.packetsReceived && (
                  <div
                    className={`text-xs mt-1 ${
                      lastNetworkStats.packetsReceived < baseline.packetsReceived * 0.8
                        ? "text-red-500"
                        : lastNetworkStats.packetsReceived > baseline.packetsReceived * 1.2
                        ? "text-green-500"
                        : "text-gray-500"
                    }`}
                  >
                    {getPercentChange(lastNetworkStats.packetsReceived, baseline.packetsReceived)} from baseline
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        <div className="w-80 border-l border-gray-300 p-6 flex-shrink-0 h-screen sticky top-0" style={{ background: 'linear-gradient(135deg, #1e1e2f 0%, #27293d 100%)' }}>
          <h3 className="text-xl font-bold mb-4" style={{ color: 'rgb(160,32,240)' }}>Simulate Attack</h3>
          <div className="bg-white p-4 rounded-lg shadow-md mb-4">
            <h4 className="text-lg font-semibold mb-2" style={{ color: 'rgb(160,32,240)' }}>Attack Type</h4>
            <button
              className="w-full py-2 rounded-lg text-white font-medium"
              onClick={handleSimulateAttack}
              disabled={!wsConnected}
              style={{
                backgroundColor: attackStatus === "started" ? 'rgb(75,75,75)' : 'rgb(160,32,240)',
                ':hover': { backgroundColor: attackStatus === "started" ? 'rgb(55,55,55)' : 'rgb(140,28,210)' }
              }}
            >
              {attackStatus === "started" ? "Stop Attack" : "Start Attack"}
            </button>
            {attackStatus === "started" && (
              <div className="text-sm text-gray-400 mt-2">
                Running {attackDetails.attackType} attack (Intensity: {(attackDetails.intensity * 100)?.toFixed(0)}%)
              </div>
            )}
          </div>
          <div className="bg-white p-4 rounded-lg shadow-md mb-4">
            <h4 className="text-lg font-semibold mb-2" style={{ color: 'rgb(160,32,240)' }}>Prevention</h4>
            <label className="flex items-center">
              <input
              disabled
                type="checkbox"
                checked={preventionEnabled}
                onChange={handleTogglePrevention}
                className="mr-2"
              />
              <span className="text-sm text-gray-700">Enable IP Blocking</span>
            </label>
          </div>
          <div className="bg-white p-4 rounded-lg shadow-md">
            <h4 className="text-lg font-semibold mb-2" style={{ color: 'rgb(160,32,240)' }}>Blocked IPs</h4>
            {blockedIPs.length === 0 ? (
              <p className="text-sm text-gray-500">No IPs blocked</p>
            ) : (
              <ul className="space-y-2">
                {blockedIPs.map((ip, index) => (
                  <li key={index} className="flex justify-between items-center text-sm">
                    <span>{ip}</span>
                    <button
                      className="rounded-lg text-white px-2 py-1"
                      onClick={() => handleUnblockIP(ip)}
                      style={{ backgroundColor: 'rgb(160,32,240)', ':hover': { backgroundColor: 'rgb(140,28,210)' } }}
                    >
                      Unblock
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </div>
    </ErrorBoundary>
  );
}

export default NIDS;