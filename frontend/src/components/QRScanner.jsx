// import React, { useState } from 'react';

// const QRScanner = ({ user, scanUrl, setScanResults }) => {
//   const [selectedFile, setSelectedFile] = useState(null);
//   const [scanning, setScanning] = useState(false);
//   const [error, setError] = useState(null);

//   const handleFileChange = (event) => {
//     setSelectedFile(event.target.files[0]);
//     setError(null);
//   };

//   const scanFile = async () => {
//     if (!selectedFile) {
//       setError('Please select a file to scan');
//       return;
//     }

//     setScanning(true);
//     setError(null);
    
//     try {
//       const reader = new FileReader();
//       reader.readAsDataURL(selectedFile);
      
//       reader.onload = async () => {
//         const base64Image = reader.result.split(',')[1];
        
//         const scanResponse = await fetch(scanUrl, {
//           method: 'POST',
//           headers: {
//             'Content-Type': 'application/json',
//           },
//           body: JSON.stringify({
//             image: base64Image,
//             filename: selectedFile.name,
//             manualUpload: true
//           })
//         });
        
//         if (!scanResponse.ok) {
//           throw new Error(`Scan failed: ${scanResponse.statusText}`);
//         }
        
//         const scanData = await scanResponse.json();
        
//         if (scanData.qrCodes && scanData.qrCodes.length > 0) {
//           setScanResults([{
//             manualUpload: true,
//             fileName: selectedFile.name,
//             date: new Date().toISOString(),
//             qrCodes: scanData.qrCodes
//           }]);
//         } else {
//           setError('No QR codes found in the image');
//         }
//       };
      
//       reader.onerror = () => {
//         throw new Error('Error reading file');
//       };
      
//     } catch (error) {
//       setError(`Error: ${error.message}`);
//       console.error('Scanning error:', error);
//     } finally {
//       setScanning(false);
//     }
//   };

//   return (
//     <div className="qr-scanner">
//       <h2>Scan Individual File</h2>
//       <div className="scanner-input">
//         <input 
//           type="file" 
//           accept="image/*,application/pdf" 
//           onChange={handleFileChange}
//           disabled={scanning}
//         />
//         <button 
//           onClick={scanFile} 
//           disabled={!selectedFile || scanning}
//           className="scan-button"
//         >
//           {scanning ? 'Scanning...' : 'Scan for QR Codes'}
//         </button>
//       </div>
      
//       {error && <div className="error-message">{error}</div>}
      
//       <div className="scanner-info">
//         <p>Upload an image or PDF file to scan for QR codes</p>
//       </div>
//     </div>
//   );
// };

// export default QRScanner;