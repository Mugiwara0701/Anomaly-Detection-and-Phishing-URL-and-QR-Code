import React, { useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import './Dashboard.css';
import { FaLock, FaFish } from 'react-icons/fa';

const Dashboard = ({ setIsLoggedIn }) => {
  const containerRef = useRef(null);
  const navigate = useNavigate();

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    setIsLoggedIn(false);
  };

  const handlePhishingClick = () => {
    navigate('/phishing');
  };

  const handleNIDSClick = () => {
    navigate('/nids');
  };

  const boxes = Array.from({ length: 30 }, (_, index) => ({
    id: index + 1,
    speed: 0.8 + Math.random() * 0.4,
    color: `rgba(${Math.random() * 255}, ${Math.random() * 255}, ${Math.random() * 255}, 0.3)`,
    size: 30 + Math.random() * 90,
    top: `${Math.random() * 80 + 10}%`,
    left: `${Math.random() * 90 + 10}%`,
    animationDuration: 5 + Math.random() * 3,
    isBox5: (index + 1) % 2 === 0,
  }));

  useEffect(() => {
    const container = containerRef.current;
    const boxElements = container.querySelectorAll('.box-3d');
    const box5Elements = container.querySelectorAll('.box-5');

    const handleMouseMove = (e) => {
      const { clientX, clientY } = e;
      const { innerWidth, innerHeight } = window;
      const x = (clientX - innerWidth / 2) / (innerWidth / 2);
      const y = (clientY - innerHeight / 2) / (innerHeight / 2);

      boxElements.forEach((box) => {
        const speed = box.getAttribute('data-speed') || 1;
        const rotateX = y * 20 * speed;
        const rotateY = x * 20 * speed;
        box.style.setProperty('--rotateX', `${rotateX}deg`);
        box.style.setProperty('--rotateY', `${rotateY}deg`);
      });
    };

    const handleMouseOver = (e) => {
      const box = e.target;
      if (!box.classList.contains('box-5')) return;
      const { clientX, clientY } = e;
      const boxRect = box.getBoundingClientRect();
      const boxCenterX = boxRect.left + boxRect.width / 2;
      const boxCenterY = boxRect.top + boxRect.height / 2;
      const deltaX = (boxCenterX - clientX) / 50;
      const deltaY = (boxCenterY - clientY) / 50;
      box.style.setProperty('--moveX', `${deltaX}px`);
      box.style.setProperty('--moveY', `${deltaY}px`);
      box.classList.add('hovered');
    };

    const handleMouseOut = (e) => {
      const box = e.target;
      if (!box.classList.contains('box-5')) return;
      box.style.setProperty('--moveX', '0px');
      box.style.setProperty('--moveY', '0px');
      box.classList.remove('hovered');
    };

    window.addEventListener('mousemove', handleMouseMove);
    box5Elements.forEach((box) => {
      box.addEventListener('mouseover', handleMouseOver);
      box.addEventListener('mouseout', handleMouseOut);
    });

    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      box5Elements.forEach((box) => {
        box.removeEventListener('mouseover', handleMouseOver);
        box.removeEventListener('mouseout', handleMouseOut);
      });
    };
  }, []);

  return (
    <div className="dashboard-container" ref={containerRef}>
      {boxes.map((box) => (
        <div
          key={box.id}
          className={`box-3d ${box.isBox5 ? 'box-5' : ''}`}
          style={{
            background: box.color,
            width: `${box.size}px`,
            height: `${box.size}px`,
            top: box.top,
            left: box.left,
            animationDuration: `${box.animationDuration}s`,
          }}
          data-speed={box.speed}
        ></div>
      ))}
      <div className="dashboard-overlay">
        <header className="dashboard-header">
          <h1 className="dashboard-title">Security Dashboard</h1>
          <button className="logout-btn" onClick={handleLogout}>
            Logout
          </button>
        </header>
        <main className="dashboard-main">
          <div className="options-container">
            <div
              className="option-card"
              onClick={handleNIDSClick}
              style={{ cursor: 'pointer' }}
            >
              <FaLock className="card-icon" />
              <h2>Network Intrusion Detection System</h2>
              <p className="card-subtitle">NIDS</p>
            </div>
            <div
              className="option-card"
              onClick={handlePhishingClick}
              style={{ cursor: 'pointer' }}
            >
              <FaFish className="card-icon" />
              <h2>Phishing URL Detector</h2>
              <p className="card-subtitle">Phishing Protection</p>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
};

export default Dashboard;