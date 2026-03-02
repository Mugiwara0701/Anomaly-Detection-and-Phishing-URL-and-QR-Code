import React from 'react';

const Login = () => {
  const API_URL = "http://localhost:8000";

  const handleLogin = async () => {
    try {
      const response = await fetch(`${API_URL}/auth/google`);
      const data = await response.json();
      if (data.auth_url) {
        window.location.href = data.auth_url;
      }
    } catch (error) {
      console.error('Login error:', error);
    }
  };

  return (
    <div className="min-h-screen bg-[rgba(30,30,47,0.9)] flex flex-col items-center justify-center text-white">
      <h2 className="text-4xl font-bold mb-4">Security Dashboard</h2>
      <p className="text-lg mb-6">Please log in with your Google account</p>
      <button 
        onClick={handleLogin} 
        className=" bg-purple-600 hover:bg-purple-700 text-white font-semibold py-2 px-4 rounded-lg transition duration-300"
      >
        Log in with Google
      </button>
    </div>
  );
};

export default Login;