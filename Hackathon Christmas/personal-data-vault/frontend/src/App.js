import React, { useState, useEffect } from 'react';
import { AlertCircle, Upload, Download, Trash2, Lock, LogOut } from 'lucide-react';
const API_URL = "http://127.0.0.1:5000";

const Alert = ({ children, variant = 'default', onClose }) => {
  const bgColor = variant === 'error' ? 'bg-red-500' : 'bg-green-500';
  
  return (
    <div className={`${bgColor} text-white p-4 rounded-lg mb-4 flex justify-between items-center`}>
      <div className="flex items-center">
        <AlertCircle className="h-4 w-4 mr-2" />
        {children}
      </div>
      <button onClick={onClose} className="text-white">&times;</button>
    </div>
  );
};

const App = () => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [activeSection, setActiveSection] = useState('files');
  const [files, setFiles] = useState([]);
  const [passwords, setPasswords] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [loginData, setLoginData] = useState({ username: '', password: '' });
  const [registerData, setRegisterData] = useState({ username: '', password: '' });
  
  const removeAlert = (index) => {
    setAlerts(alerts.filter((_, i) => i !== index));
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch(`${API_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(loginData)
      });
      const data = await response.json();
      if (response.ok) {
        localStorage.setItem('token', data.token);
        setIsAuthenticated(true);
      } else {
        setAlerts([...alerts, { type: 'error', message: data.message }]);
      }
    } catch (error) {
      setAlerts([...alerts, { type: 'error', message: 'Login failed' }]);
    }
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch(`${API_URL}/register`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json', 
          'Accept': 'application/json' },
        body: JSON.stringify(registerData),
        credentials: 'include'
      });
      const data = await response.json();
      if (!response.ok) {
        setAlerts([...alerts, { type: 'error', message: data.message || 'Registration failed' }]);
      } else {
        setAlerts([...alerts, { type: 'success', message: 'Registered successfully!' }]);
        // If you want to display the QR code:
        if (data.mfa_qr) {
          const qrImage = `data:image/png;base64,${data.mfa_qr}`;
          // You can now use qrImage in an <img> tag or store it
      }
      }
    } catch (err) {
      console.error(err);
      setAlerts([...alerts, { type: 'error', message: 'Error connecting to the server.' }]);
    }
  };

  const FileUploadSection = () => {
    const [file, setFile] = useState(null);
    const [category, setCategory] = useState('');

    const handleUpload = async (e) => {
      e.preventDefault();
      const formData = new FormData();
      formData.append('file', file);
      formData.append('category', category);

      try {
        const response = await fetch(`${API_URL}/upload`, {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` },
          body: formData
        });
        const data = await response.json();
        if (response.ok) {
          fetchFiles();
          setAlerts([...alerts, { type: 'success', message: 'File uploaded successfully' }]);
        }
      } catch (error) {
        setAlerts([...alerts, { type: 'error', message: 'Upload failed' }]);
      }
    };

    return (
      <div className="p-4 bg-gray-800 rounded-lg">
        <h2 className="text-xl font-bold mb-4">Upload File</h2>
        <form onSubmit={handleUpload} className="space-y-4">
          <input
            type="file"
            onChange={(e) => setFile(e.target.files[0])}
            className="w-full p-2 bg-gray-700 rounded"
          />
          <input
            type="text"
            placeholder="Category"
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            className="w-full p-2 bg-gray-700 rounded"
          />
          <button type="submit" className="w-full p-2 bg-blue-600 rounded hover:bg-blue-700 flex items-center justify-center">
            <Upload className="mr-2" size={16} />
            Upload
          </button>
        </form>
      </div>
    );
  };

  const PasswordSection = () => {
    const [passwordData, setPasswordData] = useState({
      site: '',
      username: '',
      password: ''
    });

    const handlePasswordSave = async (e) => {
      e.preventDefault();
      try {
        const response = await fetch(`${API_URL}/passwords`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${localStorage.getItem('token')}`
          },
          body: JSON.stringify(passwordData)
        });
        const data = await response.json();
        if (response.ok) {
          fetchPasswords();
          setAlerts([...alerts, { type: 'success', message: 'Password saved successfully' }]);
          setPasswordData({ site: '', username: '', password: '' }); // Clear form
        }
      } catch (error) {
        setAlerts([...alerts, { type: 'error', message: 'Failed to save password' }]);
      }
    };

    return (
      <div className="p-4 bg-gray-800 rounded-lg">
        <h2 className="text-xl font-bold mb-4">Password Manager</h2>
        <form onSubmit={handlePasswordSave} className="space-y-4">
          <input
            type="text"
            placeholder="Website/Service"
            value={passwordData.site}
            onChange={(e) => setPasswordData({...passwordData, site: e.target.value})}
            className="w-full p-2 bg-gray-700 rounded"
          />
          <input
            type="text"
            placeholder="Username"
            value={passwordData.username}
            onChange={(e) => setPasswordData({...passwordData, username: e.target.value})}
            className="w-full p-2 bg-gray-700 rounded"
          />
          <input
            type="password"
            placeholder="Password"
            value={passwordData.password}
            onChange={(e) => setPasswordData({...passwordData, password: e.target.value})}
            className="w-full p-2 bg-gray-700 rounded"
          />
          <button type="submit" className="w-full p-2 bg-blue-600 rounded hover:bg-blue-700 flex items-center justify-center">
            <Lock className="mr-2" size={16} />
            Save Password
          </button>
        </form>
      </div>
    );
  };

  const fetchFiles = async () => {
    try {
      const response = await fetch(`${API_URL}/files`, {
        headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
      });
      if (response.ok) {
        const data = await response.json();
        setFiles(data);
      }
    } catch (error) {
      setAlerts([...alerts, { type: 'error', message: 'Failed to fetch files' }]);
    }
  };

  const fetchPasswords = async () => {
    try {
      const response = await fetch(`${API_URL}/passwords`, {
        headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
      });
      if (response.ok) {
        const data = await response.json();
        setPasswords(data);
      }
    } catch (error) {
      setAlerts([...alerts, { type: 'error', message: 'Failed to fetch passwords' }]);
    }
  };

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      setIsAuthenticated(true);
      fetchFiles();
      fetchPasswords();
    }
  }, []);

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-gray-900 text-white p-8">
        <div className="max-w-md mx-auto space-y-8">
          <h1 className="text-3xl font-bold text-center">Personal Data Vault</h1>
          
          {alerts.map((alert, index) => (
            <Alert 
              key={index} 
              variant={alert.type === 'error' ? 'error' : 'default'}
              onClose={() => removeAlert(index)}
            >
              {alert.message}
            </Alert>
          ))}
          
          <div className="bg-gray-800 p-6 rounded-lg">
            <h2 className="text-xl font-bold mb-4">Login</h2>
            <form onSubmit={handleLogin} className="space-y-4">
              <input
                type="text"
                placeholder="Username"
                value={loginData.username}
                onChange={(e) => setLoginData({...loginData, username: e.target.value})}
                className="w-full p-2 bg-gray-700 rounded"
              />
              <input
                type="password"
                placeholder="Password"
                value={loginData.password}
                onChange={(e) => setLoginData({...loginData, password: e.target.value})}
                className="w-full p-2 bg-gray-700 rounded"
              />
              <button type="submit" className="w-full p-2 bg-blue-600 rounded hover:bg-blue-700">
                Login
              </button>
            </form>
          </div>

          <div className="bg-gray-800 p-6 rounded-lg">
            <h2 className="text-xl font-bold mb-4">Register</h2>
            <form onSubmit={handleRegister} className="space-y-4">
              <input
                type="text"
                placeholder="Username"
                value={registerData.username}
                onChange={(e) => setRegisterData({...registerData, username: e.target.value})}
                className="w-full p-2 bg-gray-700 rounded"
              />
              <input
                type="password"
                placeholder="Password"
                value={registerData.password}
                onChange={(e) => setRegisterData({...registerData, password: e.target.value})}
                className="w-full p-2 bg-gray-700 rounded"
              />
              <button type="submit" className="w-full p-2 bg-blue-600 rounded hover:bg-blue-700">
                Register
              </button>
            </form>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-900 text-white p-8">
      <div className="max-w-4xl mx-auto">
        <div className="flex justify-between items-center mb-8">
          <h1 className="text-3xl font-bold">Personal Data Vault</h1>
          <button
            onClick={() => {
              localStorage.removeItem('token');
              setIsAuthenticated(false);
            }}
            className="p-2 bg-red-600 rounded hover:bg-red-700 flex items-center"
          >
            <LogOut className="mr-2" size={16} />
            Logout
          </button>
        </div>

        {alerts.map((alert, index) => (
          <Alert 
            key={index} 
            variant={alert.type === 'error' ? 'error' : 'default'}
            onClose={() => removeAlert(index)}
          >
            {alert.message}
          </Alert>
        ))}

        <nav className="flex space-x-4 mb-8">
          <button
            onClick={() => setActiveSection('files')}
            className={`p-2 rounded ${activeSection === 'files' ? 'bg-blue-600' : 'bg-gray-700'}`}
          >
            Files
          </button>
          <button
            onClick={() => setActiveSection('passwords')}
            className={`p-2 rounded ${activeSection === 'passwords' ? 'bg-blue-600' : 'bg-gray-700'}`}
          >
            Passwords
          </button>
        </nav>

        {activeSection === 'files' && (
          <div className="space-y-8">
            <FileUploadSection />
            <div className="bg-gray-800 p-4 rounded-lg">
              <h2 className="text-xl font-bold mb-4">Your Files</h2>
              <div className="space-y-2">
                {files.map((file) => (
                  <div key={file.id} className="p-2 bg-gray-700 rounded flex justify-between items-center">
                    <span>{file.file_name}</span>
                    <span className="text-gray-400">{file.category}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {activeSection === 'passwords' && (
          <div className="space-y-8">
            <PasswordSection />
            <div className="bg-gray-800 p-4 rounded-lg">
              <h2 className="text-xl font-bold mb-4">Stored Passwords</h2>
              <div className="space-y-2">
                {passwords.map((pwd, index) => (
                  <div key={index} className="p-2 bg-gray-700 rounded flex justify-between items-center">
                    <span>{pwd.site}</span>
                    <span className="text-gray-400">{pwd.username}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default App;