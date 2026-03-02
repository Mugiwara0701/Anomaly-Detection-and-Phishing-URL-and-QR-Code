import React, { useState, useEffect, useCallback } from "react";
import DOMPurify from "dompurify";
import jsQR from "jsqr";
import "./PhishingUrl.css";
import { Mail, Menu } from "lucide-react";

class ErrorBoundary extends React.Component {
  state = { hasError: false, error: null };

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="error-message">
          <h3>Something went wrong.</h3>
          <p>{this.state.error?.message || "Unknown error"}</p>
          <button
            onClick={() => this.setState({ hasError: false, error: null })}
          >
            Try Again
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

const PhishingURL = ({ accessToken }) => {
  const [emails, setEmails] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [scanResults, setScanResults] = useState([]);
  const [activeTab, setActiveTab] = useState("emails");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [selectedEmail, setSelectedEmail] = useState(null);
  const [attachments, setAttachments] = useState({});
  const [attachmentErrors, setAttachmentErrors] = useState({});
  const [newAccessToken, setNewAccessToken] = useState(accessToken);
  const [showUrlPopup, setShowUrlPopup] = useState(false);
  const [extractedUrls, setExtractedUrls] = useState([]);
  const [urlScanResults, setUrlScanResults] = useState([]);
  const [qrUrls, setQrUrls] = useState([]);

  const API_URL = "http://localhost:8000";

  useEffect(() => {
    if (newAccessToken) {
      fetchEmails(newAccessToken);
    }
  }, [newAccessToken]);

  const fetchEmails = async (token) => {
    setLoading(true);
    setError(null);
    try {
      const refreshToken = localStorage.getItem("refresh_token");
      const response = await fetch(
        `${API_URL}/api/gmail/messages?access_token=${token}${
          refreshToken ? `&refresh_token=${refreshToken}` : ""
        }&max_results=60`
      );
      if (!response.ok) {
        if (response.status === 401) {
          throw new Error(
            "Invalid or expired access token. Please log in again."
          );
        }
        throw new Error(`API error: ${response.status}`);
      }
      const data = await response.json();
      if (data.new_access_token) {
        localStorage.setItem("access_token", data.new_access_token);
        setNewAccessToken(data.new_access_token);
      }
      setEmails(data.messages || []);
    } catch (err) {
      setError(`Failed to fetch emails: ${err.message}`);
      console.error("Error fetching emails:", err);
    } finally {
      setLoading(false);
    }
  };

  const fetchAttachment = async (emailId, attachmentId) => {
    console.log(`Fetching attachment ${attachmentId} for email ${emailId}`);
    try {
      const accessToken = localStorage.getItem("access_token");
      const refreshToken = localStorage.getItem("refresh_token");
      const response = await fetch(
        `${API_URL}/api/gmail/messages/${emailId}/attachments/${attachmentId}?access_token=${accessToken}${
          refreshToken ? `&refresh_token=${refreshToken}` : ""
        }`,
        {
          credentials: "include",
        }
      );

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || "Failed to fetch attachment");
      }

      const data = await response.json();
      if (!data.data) {
        throw new Error("No attachment data received");
      }

      try {
        atob(data.data);
        console.log(`Base64 data valid for attachment ${attachmentId}, length: ${data.data.length}`);
      } catch (e) {
        throw new Error(`Invalid base64 data received for attachment ${attachmentId}`);
      }

      let inferredMimeType = data.mimeType;
      if (inferredMimeType === "application/octet-stream") {
        const binaryData = atob(data.data);
        const firstBytes = binaryData.slice(0, 4);
        if (firstBytes.startsWith("\x89PNG")) {
          inferredMimeType = "image/png";
        } else if (firstBytes.startsWith("\xFF\xD8")) {
          inferredMimeType = "image/jpeg";
        } else if (firstBytes.startsWith("GIF8")) {
          inferredMimeType = "image/gif";
        }
      }

      console.log("Attachment fetched:", {
        emailId,
        attachmentId,
        mimeType: inferredMimeType,
        dataLength: data.data.length,
        dataPreview: data.data.slice(0, 50),
      });

      return {
        mimeType: inferredMimeType,
        data: data.data,
      };
    } catch (error) {
      console.error(`Error fetching attachment ${attachmentId}:`, error);
      throw error;
    }
  };

  const getEmailBody = useCallback((email) => {
    if (!email)
      return {
        body: "No content",
        inlineImages: [],
        pdfs: [],
        links: [],
        qrCodes: [],
      };

    const parts = email.payload?.parts || [];
    let body = "";
    const inlineImages = [];
    const pdfs = [];
    const links = [];

    const processParts = (parts) => {
      for (const part of parts) {
        if (part.mimeType === "text/plain") {
          const decoded = part.body?.data
            ? atob(part.body.data.replace(/-/g, "+").replace(/_/g, "/"))
            : "";
          body += decoded;
        } else if (part.mimeType === "text/html") {
          const decoded = part.body?.data
            ? atob(part.body.data.replace(/-/g, "+").replace(/_/g, "/"))
            : "";
          body += decoded;
          const parser = new DOMParser();
          const doc = parser.parseFromString(decoded, "text/html");
          const anchors = doc.querySelectorAll("a[href]");
          anchors.forEach((a) => {
            const href = a.getAttribute("href");
            if (href?.startsWith("http")) links.push(href);
          });
        } else if (
          (part.mimeType?.startsWith("image/") &&
            ["image/png", "image/jpeg", "image/gif"].includes(part.mimeType)) ||
          (part.mimeType === "application/octet-stream" &&
            part.filename &&
            /\.(png|jpg|jpeg|gif)$/i.test(part.filename))
        ) {
          const attachmentId = part.body?.attachmentId;
          if (part.body?.data) {
            const base64Data = part.body.data
              .replace(/-/g, "+")
              .replace(/_/g, "/");
            try {
              atob(base64Data);
              inlineImages.push({
                mimeType: part.mimeType,
                body: { data: base64Data },
                filename: part.filename || `inline-image-${inlineImages.length}`,
              });
            } catch (e) {
              console.error(`Invalid base64 data for inline image:`, e);
            }
          } else if (attachmentId && part.filename) {
            inlineImages.push({
              mimeType: part.mimeType,
              body: { attachmentId },
              filename: part.filename,
            });
          }
        } else if (part.mimeType === "application/pdf" && part.filename) {
          const attachmentId = part.body?.attachmentId;
          if (attachmentId) {
            pdfs.push({
              mimeType: part.mimeType,
              body: { attachmentId },
              filename: part.filename,
            });
          }
        } else if (part.parts) {
          processParts(part.parts);
        }
      }
    };

    if (parts.length > 0) {
      processParts(parts);
    } else if (email.payload?.body?.data) {
      const decoded = atob(
        email.payload.body.data.replace(/-/g, "+").replace(/_/g, "/")
      );
      if (email.payload.mimeType === "text/plain") {
        body = decoded;
      } else if (email.payload.mimeType === "text/html") {
        body = decoded;
        const parser = new DOMParser();
        const doc = parser.parseFromString(decoded, "text/html");
        const anchors = doc.querySelectorAll("a[href]");
        anchors.forEach((a) => {
          const href = a.getAttribute("href");
          if (href?.startsWith("http")) links.push(href);
        });
      }
    }

    return { body, inlineImages, pdfs, links: [...new Set(links)], qrCodes: [] };
  }, []);

  const scanUrls = async () => {
    if (!extractedUrls.length) {
      setError("No URLs to scan");
      return;
    }
    setLoading(true);
    try {
      const response = await fetch(`${API_URL}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          image: null,
          links: extractedUrls,
          accessToken: newAccessToken,
        }),
      });
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || `Scan API error: ${response.status}`);
      }
      const data = await response.json();
      if (data.new_access_token) {
        localStorage.setItem("access_token", data.new_access_token);
        setNewAccessToken(data.new_access_token);
      }
      setUrlScanResults(data.phishingLinks || []);
    } catch (err) {
      setError(`Failed to scan URLs: ${err.message}`);
      console.error("Error scanning URLs:", err);
    } finally {
      setLoading(false);
    }
  };

  const scanImagesForQRCodes = async (images, newAttachments) => {
    const qrCodes = [];
    for (const img of images) {
      let base64Image = img.body.data;
      const attachmentId = img.body.attachmentId;
      if (!base64Image && attachmentId) {
        base64Image = newAttachments[attachmentId]?.data;
        console.log(`Retrieved base64 for ${attachmentId}: ${base64Image ? `length ${base64Image.length}` : 'not found'}`);
      }
      if (!base64Image) {
        console.warn(`No base64 data for image: ${img.filename || "unknown"} (attachmentId: ${attachmentId || "none"})`);
        setError(`No base64 data for image: ${img.filename || "unknown"}`);
        continue;
      }

      console.log(`Scanning image: ${img.filename || "unknown"} (MIME: ${img.mimeType}, base64 length: ${base64Image.length}, base64 preview: ${base64Image.slice(0, 50)})`);

      try {
        try {
          atob(base64Image);
        } catch (e) {
          console.error(`Invalid base64 data for image ${img.filename || "unknown"}:`, e);
          setError(`Invalid base64 data for image: ${img.filename || "unknown"}`);
          continue;
        }

        const image = new Image();
        const loadPromise = new Promise((resolve, reject) => {
          image.onload = () => {
            console.log(`Image loaded: ${img.filename || "unknown"} (${image.width}x${image.height})`);
            resolve();
          };
          image.onerror = () => {
            reject(new Error(`Failed to load image ${img.filename || "unknown"}`));
          };
          image.src = `data:${img.mimeType};base64,${base64Image}`;
        });
        await loadPromise;

        const canvas = document.createElement("canvas");
        canvas.width = image.width;
        canvas.height = image.height;
        const ctx = canvas.getContext("2d");
        ctx.drawImage(image, 0, 0);
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

        const qrCode = jsQR(imageData.data, imageData.width, imageData.height);
        if (qrCode && qrCode.data) {
          console.log(`QR code found in image ${img.filename || "unknown"}: ${qrCode.data}`);
          qrCodes.push({ content: qrCode.data });
        } else {
          console.log(`No QR code found in image: ${img.filename || "unknown"}`);
        }
      } catch (err) {
        console.error(`Error scanning image ${img.filename || "unknown"} for QR codes:`, err);
        setError(`Failed to scan image ${img.filename || "unknown"}: ${err.message}`);
      }
    }
    return qrCodes;
  };

  const extractImagesFromPDF = async (emailId, attachmentId, filename) => {
    try {
        const accessToken = localStorage.getItem("access_token");
        const refreshToken = localStorage.getItem("refresh_token");
        const response = await fetch(
            `${API_URL}/api/gmail/messages/${emailId}/attachments/${attachmentId}?access_token=${accessToken}${
                refreshToken ? `&refresh_token=${refreshToken}` : ""
            }`,
            { credentials: "include" }
        );
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || "Failed to fetch PDF");
        }
        const data = await response.json();
        if (!data.data) {
            throw new Error("No PDF data received");
        }
        console.log(`Fetched PDF: ${filename}, mimeType: ${data.mimeType}`);
        const extractResponse = await fetch(`${API_URL}/api/extract-pdf-images`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                pdfData: data.data,
                accessToken: newAccessToken,
            }),
        });
        if (!extractResponse.ok) {
            const errorData = await extractResponse.json();
            throw new Error(errorData.detail || `Extract PDF images API error: ${extractResponse.status}`);
        }
        const extractData = await extractResponse.json();
        if (extractData.new_access_token) {
            localStorage.setItem("access_token", extractData.new_access_token);
            setNewAccessToken(extractData.new_access_token);
        }
        return extractData.images || [];
    } catch (error) {
        console.error(`Error extracting images from PDF ${filename}:`, error);
        if (error.message.includes("Poppler is not installed")) {
            setError("PDF processing failed: Poppler is not installed on the server. Contact the administrator.");
        } else {
            setError(`Failed to process PDF ${filename}: ${error.message}`);
        }
        return [];
    }
};

  const handleEmailSelect = useCallback(
    async (email) => {
      console.log("Selected email ID:", email.id);
      setSelectedEmail(email);
      setError(null);
      setExtractedUrls([]);
      setUrlScanResults([]);
      setQrUrls([]);
      setAttachmentErrors({});
      const { inlineImages, pdfs, links } = getEmailBody(email);
      console.log(
        "Inline images found:",
        inlineImages.map((img) => img.body.attachmentId || "inline")
      );
      console.log("PDFs found:", pdfs.map((pdf) => pdf.filename));
      const newAttachments = { ...attachments };
      const newErrors = {};

      for (const img of inlineImages) {
        const attachmentId = img.body.attachmentId;
        if (!attachmentId || newAttachments[attachmentId] || newErrors[attachmentId]) continue;
        try {
          await new Promise((resolve) => setTimeout(resolve, 100));
          const data = await fetchAttachment(email.id, attachmentId);
          if (data?.data) {
            newAttachments[attachmentId] = {
              mimeType: data.mimeType,
              data: data.data,
            };
            console.log(`Stored attachment ${attachmentId}, MIME: ${data.mimeType}, data length: ${data.data.length}`);
          } else {
            throw new Error("No attachment data received");
          }
        } catch (error) {
          console.error(`Failed to fetch image attachment ${attachmentId}:`, error);
          newErrors[attachmentId] = error.message || "Failed to fetch image";
        }
      }

      const pdfImages = [];
      for (const pdf of pdfs) {
        const attachmentId = pdf.body.attachmentId;
        if (!attachmentId || newAttachments[attachmentId] || newErrors[attachmentId]) continue;
        try {
          await new Promise((resolve) => setTimeout(resolve, 100));
          const images = await extractImagesFromPDF(email.id, attachmentId, pdf.filename);
          pdfImages.push(
            ...images.map((img, index) => ({
              mimeType: img.mimeType || "image/png",
              body: { data: img.data.replace(/^data:image\/[a-z]+;base64,/, "") },
              filename: `${pdf.filename}_image_${index + 1}`,
            }))
          );
          newAttachments[attachmentId] = {
            data: "processed",
            mimeType: "application/pdf",
          };
        } catch (error) {
          console.error(`Failed to process PDF ${pdf.filename}:`, error);
          newErrors[attachmentId] = error.message || "Failed to process PDF";
        }
      }

      console.log("New attachments before state update:", newAttachments);
      setAttachments(newAttachments);
      setAttachmentErrors((prev) => ({ ...prev, ...newErrors }));

      const imagesToScan = [
        ...inlineImages.filter((img) => img.body.data || newAttachments[img.body.attachmentId]?.data),
        ...pdfImages,
      ];
      console.log("Images to scan for QR codes:", imagesToScan.map((img) => ({
        filename: img.filename,
        attachmentId: img.body.attachmentId,
        hasData: !!img.body.data,
        hasAttachmentData: !!newAttachments[img.body.attachmentId]?.data,
      })));
      const qrCodes = await scanImagesForQRCodes(imagesToScan, newAttachments);
      const qrCodeUrls = qrCodes
        .map((qr) => qr.content)
        .filter((url) => url.startsWith("http"));
      console.log("QR code URLs found:", qrCodeUrls);
      setQrUrls(qrCodeUrls);
      setExtractedUrls([...new Set([...links, ...qrCodeUrls])]);
    },
    [getEmailBody, newAccessToken, attachments]
  );

  const handleExtractUrls = () => {
    setShowUrlPopup(true);
  };

  return (
    <ErrorBoundary>
      <style>{`
        @import url('https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css');
      `}</style>
      <div className="phishing-app">
        <header className="app-header">
          <div className="header-left">
            <button
              className="menu-button"
              onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
            >
              <Menu size={24} />
            </button>
            <h1 className="app-title">QR Phishing Detector</h1>
          </div>
          {/* <div className="search-container">
            <Search size={20} />
            <input type="text" placeholder="Search emails..." />
          </div> */}
        </header>

        {error && <div className="error-message">{error}</div>}
        {loading && <div className="loading-message">Loading...</div>}

        <div className="main-content">
          <aside className={`sidebar ${sidebarCollapsed ? "collapsed" : ""}`}>
            <nav className="sidebar-nav">
              <button
                className={activeTab === "emails" ? "active" : ""}
                onClick={() => setActiveTab("emails")}
              >
                <Mail size={20} />
                {!sidebarCollapsed && <span>Inbox</span>}
              </button>
              {/* <button
                className={activeTab === "scanner" ? "active" : ""}
                onClick={() => setActiveTab("scanner")}
              >
                <QrCode size={20} />
                {!sidebarCollapsed && <span>QR Scanner</span>}
              </button>
              <button
                className={activeTab === "history" ? "active" : ""}
                onClick={() => setActiveTab("history")}
              >
                <History size={20s} />
                {!sidebarCollapsed && <span>Scan History</span>}
              </button> */}
              {activeTab === "emails" &&
                !sidebarCollapsed &&
                emails.length > 0 && (
                  <div className="email-sender-list">
                    {emails.map((email) => {
                      const fromHeader =
                        email.payload?.headers?.find((h) => h.name === "From")
                          ?.value || "Unknown Sender";
                      return (
                        <button
                          key={email.id}
                          className={
                            selectedEmail?.id === email.id ? "active" : ""
                          }
                          onClick={() => handleEmailSelect(email)}
                        >
                          <span className="sender-name">
                            {fromHeader.split("<")[0].trim()}
                          </span>
                          <span className="email-snippet">
                            {email.snippet?.substring(0, 50) || "No preview"}...
                          </span>
                        </button>
                      );
                    })}
                  </div>
                )}
            </nav>
          </aside>

          <main className="content-area">
            {activeTab === "emails" && (
              <div className="email-content-wrapper">
                {selectedEmail ? (
                  <div className="email-content">
                    <div className="email-header">
                      <h2>
                        {selectedEmail.payload?.headers?.find(
                          (h) => h.name === "Subject"
                        )?.value || "No Subject"}
                      </h2>
                      <p>
                        <strong>From:</strong>{" "}
                        {selectedEmail.payload?.headers?.find(
                          (h) => h.name === "From"
                        )?.value || "Unknown Sender"}
                      </p>
                      <p>
                        <strong>To:</strong>{" "}
                        {selectedEmail.payload?.headers?.find(
                          (h) => h.name === "To"
                        )?.value || "Not specified"}
                      </p>
                      <p>
                        <strong>Date:</strong>{" "}
                        {selectedEmail.payload?.headers?.find(
                          (h) => h.name === "Date"
                        )?.value || "No Date"}
                      </p>
                      <button
                        className="detect-button"
                        onClick={handleExtractUrls}
                        disabled={loading}
                      >
                        Extract URLs
                      </button>
                    </div>
                    <div className="email-body-wrapper">
                      {(getEmailBody(selectedEmail).inlineImages.length > 0 ||
                        getEmailBody(selectedEmail).pdfs.length > 0) && (
                        <div className="attachments">
                          {getEmailBody(selectedEmail).inlineImages.map(
                            (img, index) => {
                              const attachmentId = img.body.attachmentId;
                              const base64Data =
                                img.body.data ||
                                attachments[attachmentId]?.data;
                              const isValidMimeType =
                                img.mimeType?.startsWith("image/") &&
                                [
                                  "image/png",
                                  "image/jpeg",
                                  "image/gif",
                                ].includes(img.mimeType);
                              if (attachmentErrors[attachmentId]) {
                                return (
                                  <div key={index} className="placeholder">
                                    Failed to load image:{" "}
                                    {attachmentErrors[attachmentId]}
                                  </div>
                                );
                              }
                              if (base64Data && isValidMimeType) {
                                try {
                                  atob(base64Data);
                                  return (
                                    <img
                                      key={index}
                                      src={`data:${img.mimeType};base64,${base64Data}`}
                                      alt={`Inline Image ${index}`}
                                      className="inline-image"
                                      onError={(e) => {
                                        console.error(
                                          `Failed to load image ${attachmentId || index}`
                                        );
                                        e.target.src = "/fallback-image.png";
                                      }}
                                    />
                                  );
                                } catch (e) {
                                  console.error(
                                    `Invalid base64 data for image ${attachmentId || index}:`,
                                    e
                                  );
                                  return (
                                    <div key={index} className="placeholder">
                                      Invalid image data
                                    </div>
                                  );
                                }
                              }
                              return (
                                <div key={index} className="placeholder">
                                  Loading image...
                                </div>
                              );
                            }
                          )}
                          {getEmailBody(selectedEmail).pdfs.map(
                            (pdf, index) => (
                              <div
                                key={`pdf-${index}`}
                                className="pdf-attachment"
                              >
                                <p>
                                  PDF: {pdf.filename} (Scanned for QR codes)
                                </p>
                                {attachmentErrors[pdf.body.attachmentId] && (
                                  <p className="error">
                                    Error:{" "}
                                    {attachmentErrors[pdf.body.attachmentId]}
                                  </p>
                                )}
                              </div>
                            )
                          )}
                        </div>
                      )}
                      <div
                        className="email-body"
                        dangerouslySetInnerHTML={{
                          __html: DOMPurify.sanitize(
                            getEmailBody(selectedEmail).body ||
                              "No content available"
                          ),
                        }}
                      />
                    </div>
                  </div>
                ) : (
                  <div className="placeholder">
                    Select an email to view its content
                  </div>
                )}
              </div>
            )}
            {activeTab === "scanner" && (
              <QRScanner
                user={{ accessToken: newAccessToken }}
                scanUrl={`${API_URL}/api/scan`}
                setScanResults={setScanResults}
              />
            )}
            {activeTab === "history" && <ScanHistory />}
            {showUrlPopup && (
              <div className="url-popup">
                <div className="url-popup-content">
                  <h3>Extracted URLs</h3>
                  {extractedUrls.length > 0 ? (
                    <>
                      <div className="url-popup-buttons">
                        <button onClick={scanUrls} disabled={loading}>
                          {loading ? "Scanning..." : "Scan URL"}
                        </button>
                        <button onClick={() => setShowUrlPopup(false)}>
                          Close
                        </button>
                      </div>
                      <h4>URLs from Email Body and QR Codes</h4>
                      <ul className="url-list">
                        {extractedUrls.map((url, index) => {
                          const scanResult = urlScanResults.find(
                            (result) => result.url === url
                          );
                          return (
                            <li
                              key={index}
                              className={`${
                                scanResult
                                  ? scanResult.is_phishing
                                    ? "text-red-600 phishing"
                                    : "text-green-600 safe"
                                  : "text-gray-600"
                              }`}
                            >
                              {url}{" "}
                              {qrUrls.includes(url)
                                ? "(From QR Code)"
                                : "(From Email Body)"}
                              {scanResult && (
                                <span>
                                  {" - "}
                                  {scanResult.is_phishing ? "Flagged" : "Safe"}
                                </span>
                              )}
                            </li>
                          );
                        })}
                      </ul>
                      {/* {urlScanResults.length > 0 && (
                        <div className="scan-results">
                          <h4>Scan Results</h4>
                          <ul>
                            {urlScanResults.map((result, index) => (
                              <li
                                key={index}
                                className={
                                  result.is_phishing
                                    ? "text-red-600 phishing"
                                    : "text-green-600 safe"
                                }
                              >
                                {result.url} -{" "}
                                {result.is_phishing ? "Phishing" : "Safe"}{" "}
                                (Confidence:{" "}
                                {(result.confidence * 100).toFixed(2)}%)
                                {result.threatDetails &&
                                  ` - ${result.threatDetails}`}
                                {result.whoisDetails &&
                                  ` | WHOIS: ${result.whoisDetails}`}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )} */}
                    </>
                  ) : (
                    <p>No URLs found in the email or QR codes.</p>
                  )}
                </div>
              </div>
            )}
          </main>
        </div>
      </div>
    </ErrorBoundary>
  );
};

export default PhishingURL;