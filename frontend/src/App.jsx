import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, useLocation } from 'react-router-dom';
import Login from './components/Login';
import Dashboard from './components/Dashboard';
import NIDS from './components/NIDS';
import PhishingURL from './components/PhishingURL';
import './App.css';

const AppContent = () => {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [accessToken, setAccessToken] = useState(null);
  const [refreshToken, setRefreshToken] = useState(null);
  const location = useLocation();

  useEffect(() => {
    const storedToken = localStorage.getItem('access_token');
    if (storedToken) {
      setAccessToken(storedToken);
      setIsLoggedIn(true);
      return;
    }
    const query = new URLSearchParams(location.search);
    const token = query.get("access_token");
    const refresh = query.get("refresh_token");

    if (token && location.pathname === '/dashboard') {
      setAccessToken(token);
      setIsLoggedIn(true);
      localStorage.setItem('access_token', token);
      if (refresh) {
        setRefreshToken(refresh);
        localStorage.setItem('refresh_token', refresh);
      }
      window.history.replaceState({}, document.title, '/dashboard');
    }
  }, [location]);

  return (
    <Routes>
      <Route 
        path="/" 
        element={!isLoggedIn ? <Login /> : <Navigate to="/dashboard" />}
      />
      <Route 
        path="/dashboard" 
        element={isLoggedIn ? <Dashboard setIsLoggedIn={setIsLoggedIn} /> : <Navigate to="/" />}
      />
      <Route 
        path="/nids" 
        element={isLoggedIn ? <NIDS accessToken={accessToken} /> : <Navigate to="/" />}
      />
      <Route 
        path="/phishing" 
        element={isLoggedIn ? <PhishingURL accessToken={accessToken} /> : <Navigate to="/" />}
      />
    </Routes>
  );
};

const App = () => {
  return (
    <Router>
      <AppContent />
    </Router>
  );
};

export default App;