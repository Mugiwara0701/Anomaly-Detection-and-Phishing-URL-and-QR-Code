// // src/Components/ScanHistory.js
// import React, { useState, useEffect } from 'react';

// const ScanHistory = () => {
//   const [history, setHistory] = useState([]);
//   const [expandedItem, setExpandedItem] = useState(null);

//   useEffect(() => {
//     const savedHistory = localStorage.getItem('qrScanHistory');
//     if (savedHistory) {
//       try {
//         setHistory(JSON.parse(savedHistory));
//       } catch (error) {
//         console.error('Error loading scan history:', error);
//       }
//     }
//   }, []);

//   const clearHistory = () => {
//     if (window.confirm('Are you sure you want to clear all scan history?')) {
//       localStorage.removeItem('qrScanHistory');
//       setHistory([]);
//       setExpandedItem(null);
//     }
//   };

//   const toggleExpandItem = (index) => {
//     if (expandedItem === index) {
//       setExpandedItem(null);
//     } else {
//       setExpandedItem(index);
//     }
//   };

//   const formatDate = (dateString) => {
//     try {
//       const date = new Date(dateString);
//       return date.toLocaleString();
//     } catch (e) {
//       return dateString || 'Unknown Date';
//     }
//   };

//   const formatQRContent = (content) => {
//     if (content.startsWith('http://') || content.startsWith('https://')) {
//       return (
//         <a href={content} target="_blank" rel="noopener noreferrer">
//           {content}
//         </a>
//       );
//     }
    
//     return content;
//   };

//   if (history.length === 0) {
//     return (
//       <div className="scan-history empty">
//         <h2>Scan History</h2>
//         <p>No saved scan results yet</p>
//       </div>
//     );
//   }

//   return (
//     <div className="scan-history">
//       <div className="history-header">
//         <h2>Scan History</h2>
//         <button onClick={clearHistory} className="clear-button">
//           Clear History
//         </button>
//       </div>
      
//       <div className="history-list">
//         {history.map((historyEntry, entryIndex) => (
//           <div 
//             key={entryIndex} 
//             className={`history-entry ${expandedItem === entryIndex ? 'expanded' : ''}`}
//           >
//             <div 
//               className="history-entry-header" 
//               onClick={() => toggleExpandItem(entryIndex)}
//             >
//               <div className="history-title">
//                 {historyEntry.timestamp && (
//                   <span className="history-date">
//                     {formatDate(historyEntry.timestamp)}
//                   </span>
//                 )}
//                 <span className="history-count">
//                   {historyEntry.results.length} {historyEntry.results.length === 1 ? 'result' : 'results'}
//                 </span>
//               </div>
//               <span className="expand-icon">
//                 {expandedItem === entryIndex ? '▼' : '▶'}
//               </span>
//             </div>
            
//             {expandedItem === entryIndex && (
//               <div className="history-details">
//                 {historyEntry.results.map((result, resultIndex) => (
//                   <div key={resultIndex} className="history-result">
//                     <div className="result-source">
//                       {result.manualUpload ? (
//                         <div>Manual Upload: {result.fileName}</div>
//                       ) : (
//                         <div>
//                           Email: {result.subject}
//                           <div className="source-detail">
//                             {result.date && `Date: ${result.date}`}
//                           </div>
//                           {result.attachmentName && (
//                             <div className="source-detail">
//                               Attachment: {result.attachmentName}
//                             </div>
//                           )}
//                         </div>
//                       )}
//                     </div>
                    
//                     <ul className="history-qr-list">
//                       {result.qrCodes.map((qrCode, qrIndex) => (
//                         <li key={qrIndex} className="history-qr-item">
//                           {formatQRContent(qrCode.content)}
//                         </li>
//                       ))}
//                     </ul>
//                   </div>
//                 ))}
//               </div>
//             )}
//           </div>
//         ))}
//       </div>
//     </div>
//   );
// };

// export default ScanHistory;