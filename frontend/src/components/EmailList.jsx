import React, {useState} from 'react';

const EmailList = ({ email, user, scanUrl, setScanResults }) => {
  if (!email) {
    return <div className="error-message">Email data is not available</div>;  
  }

  const [expanded, setExpanded] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState(null);
  
  const headers = email.payload?.headers || [];
  const subject = headers.find(h => h.name === 'Subject')?.value || 'No Subject';
  const from = headers.find(h => h.name === 'From')?.value || 'Unknown Sender';
  const date = headers.find(h => h.name === 'Date')?.value || '';
  
  const formattedDate = (() => {
    try {
      const emailDate = new Date(date);
      return emailDate.toLocaleString();
    } catch (e) {
      return date;
    }
  })();
  
  const parts = email.payload?.parts || [];
  const attachments = parts.filter(part => 
    part.mimeType && 
    (part.mimeType.includes('image/') || part.mimeType.includes('application/pdf')) &&
    part.body && 
    part.body.attachmentId
  );
  
  const toggleExpand = () => {
    setExpanded(!expanded);
  };
  
  const scanAttachments = async () => {
    setScanning(true);
    setScanError(null);
    
    let found = [];
    
    for (const part of attachments) {
      try {
        const attachmentResponse = await fetch(
          `https://www.googleapis.com/gmail/v1/users/me/messages/${email.id}/attachments/${part.body.attachmentId}?access_token=${user.access_token}`
        );
        
        if (!attachmentResponse.ok) {
          throw new Error(`Failed to fetch attachment: ${attachmentResponse.statusText}`);
        }
        
        const attachmentData = await attachmentResponse.json();
        
        const imageData = attachmentData.data.replace(/-/g, '+').replace(/_/g, '/');
        
        const scanResponse = await fetch(scanUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            image: imageData,
            filename: part.filename || 'attachment.jpg',
            emailId: email.id,
            emailSubject: subject,
            emailDate: date
          })
        });
        
        if (!scanResponse.ok) {
          throw new Error(`Scan failed: ${scanResponse.statusText}`);
        }
        
        const scanData = await scanResponse.json();
        
        if (scanData.qrCodes && scanData.qrCodes.length > 0) {
          found.push({
            emailId: email.id,
            subject: subject,
            date: formattedDate,
            qrCodes: scanData.qrCodes,
            attachmentName: part.filename || 'attachment'
          });
        }
      } catch (error) {
        setScanError(`Error: ${error.message}`);
        console.error('Scanning error:', error);
      }
    }
    
    setScanning(false);
    
    if (found.length > 0) {
      setScanResults(found);
    }
  };

  return (
    <div className={`email-item ${expanded ? 'expanded' : ''}`}>
      <div className="email-header" onClick={toggleExpand}>
        <div className="email-from">{from}</div>
        <div className="email-subject">{subject}</div>
        <div className="email-date">{formattedDate}</div>
        <div className="email-expand">{expanded ? '▼' : '▶'}</div>
      </div>
      
      {expanded && (
        <div className="email-details">
          {attachments.length > 0 ? (
            <div className="email-attachments">
              <div className="attachments-header">
                <h4>Attachments ({attachments.length})</h4>
                <button 
                  onClick={scanAttachments} 
                  disabled={scanning}
                  className="scan-button small"
                >
                  {scanning ? 'Scanning...' : 'Scan Attachments'}
                </button>
              </div>
              
              {scanError && <div className="error-message">{scanError}</div>}
              
              <ul className="attachments-list">
                {attachments.map((part, index) => (
                  <li key={index} className="attachment-item">
                    {part.filename || `Attachment ${index + 1}`} ({part.mimeType})
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            <div className="no-attachments">No scannable attachments</div>
          )}
        </div>
      )}
    </div>
  );
};

export default EmailList;