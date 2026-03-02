import React from 'react';

const ScanResults = ({ results, saveToHistory }) => {
  const handleSaveAll = () => {
    if (saveToHistory && results.length > 0) {
      saveToHistory(results);
    }
  };

  const formatQRContent = (content) => {
    if (content.startsWith('http://') || content.startsWith('https://')) {
      return (
        <a href={content} target="_blank" rel="noopener noreferrer">
          {content}
        </a>
      );
    }
    
    return content;
  };

  if (!results || results.length === 0) {
    return <div className="no-results">No QR codes found</div>;
  }

  return (
    <div className="scan-results">
      <div className="results-header">
        <h2>Scan Results</h2>
        <button onClick={handleSaveAll} className="save-button">
          Save All Results to History
        </button>
      </div>
      
      <div className="results-list">
        {results.map((result, index) => (
          <div key={index} className="result-item">
            <div className="result-header">
              {result.manualUpload ? (
                <h3>Manually Uploaded: {result.fileName}</h3>
              ) : (
                <h3>
                  Email: {result.subject}
                  <span className="result-date">{result.date}</span>
                </h3>
              )}
              <div className="attachment-info">
                {result.attachmentName && `Attachment: ${result.attachmentName}`}
              </div>
            </div>
            
            <div className="qr-codes-list">
              <h4>QR Codes Found: {result.qrCodes.length}</h4>
              <ul>
                {result.qrCodes.map((qrCode, qrIndex) => (
                  <li key={qrIndex} className="qr-code-item">
                    <div className="qr-content">
                      {formatQRContent(qrCode.content)}
                    </div>
                    {qrCode.type && (
                      <div className="qr-type">Type: {qrCode.type}</div>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default ScanResults;