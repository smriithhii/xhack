const API_URL = "http://127.0.0.1:5000/api";

async function register() {
    const username = document.getElementById("register-username").value;
    const password = document.getElementById("register-password").value;

    const response = await fetch(`${API_URL}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
    });

    const data = await response.json();
    alert(data.message);
}

async function login() {
    const username = document.getElementById("login-username").value;
    const password = document.getElementById("login-password").value;

    const response = await fetch(`${API_URL}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
    });

    const data = await response.json();
    if (response.ok) {
        localStorage.setItem("token", data.token);
        document.getElementById("auth-section").style.display = "none";
        document.getElementById("dashboard").style.display = "block";
        listFiles();
    } else {
        alert(data.message);
    }
}

async function uploadFile() {
    const file = document.getElementById("file-upload").files[0];
    const category = document.getElementById("file-category").value;
    const formData = new FormData();
    formData.append("file", file);
    formData.append("category", category);

    const response = await fetch(`${API_URL}/upload`, {
        method: "POST",
        headers: { Authorization: `Bearer ${localStorage.getItem("token")}` },
        body: formData
    });

    const data = await response.json();
    alert(data.message);
    listFiles();
}

async function listFiles() {
    const response = await fetch(`${API_URL}/files`, {
        headers: { Authorization: `Bearer ${localStorage.getItem("token")}` }
    });

    const files = await response.json();
    const fileList = document.getElementById("file-list");
    fileList.innerHTML = files.map(file => `<li>${file.file_name} - ${file.category}</li>`).join("");
}

// File Sharing
async function shareFile() {
    if (!checkSession()) return;
    
    try {
        const fileId = document.getElementById('file-to-share').value;
        const username = document.getElementById('share-with-username').value;

        if (!fileId || !username) {
            showModal('Error', 'Please select a file and enter a username');
            return;
        }

        const response = await fetch(`${API_URL}/share`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            },
            body: JSON.stringify({ file_id: fileId, username })
        });

        const data = await response.json();
        showModal('Success', data.message);
        loadSharedFiles();
    } catch (error) {
        showModal('Error', 'Failed to share file');
    }
}

// Password Management
async function addPassword() {
    if (!checkSession()) return;
    
    try {
        const site = document.getElementById('password-site').value;
        const username = document.getElementById('password-username').value;
        const password = document.getElementById('password-password').value;

        if (!site || !username || !password) {
            showModal('Error', 'All fields are required');
            return;
        }

        const response = await fetch(`${API_URL}/passwords`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            },
            body: JSON.stringify({ site, username, password })
        });

        const data = await response.json();
        showModal('Success', data.message);
        loadPasswords();
    } catch (error) {
        showModal('Error', 'Failed to save password');
    }
}

async function checkBreaches() {
    const response = await fetch(`${API_URL}/check-breaches`, {
        headers: { Authorization: `Bearer ${localStorage.getItem("token")}` }
    });

    const data = await response.json();
    if (data.breaches.length > 0) {
        displayBreachAlert(data.breaches);
    }
}

// Breach Detection
async function checkBreaches() {
    if (!checkSession()) return;
    
    try {
        const response = await fetch(`${API_URL}/check-breaches`, {
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            }
        });

        const data = await response.json();
        if (data.breaches.length > 0) {
            const alertHtml = data.breaches.map(breach => 
                `<div class="breach-alert">
                    <h4>${breach.service}</h4>
                    <p>${breach.description}</p>
                </div>`
            ).join('');
            document.getElementById('breach-alerts').innerHTML = alertHtml;
        } else {
            document.getElementById('breach-alerts').innerHTML = 
                '<p class="success">No breaches detected!</p>';
        }
    } catch (error) {
        showModal('Error', 'Failed to check for breaches');
    }
}

function logout() {
    localStorage.removeItem('token');
    showSection('auth');
}

// UI Management
function showSection(section) {
    document.querySelectorAll('.dashboard-section').forEach(el => el.style.display = 'none');
    document.getElementById(`${section}-section`)?.style.display = 'block';
}

// Modal Management
function showModal(title, message) {
    document.getElementById('modal-title').textContent = title;
    document.getElementById('modal-message').textContent = message;
    document.getElementById('alert-modal').style.display = 'block';
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    checkSession();
    document.querySelector('.close').onclick = () => {
        document.getElementById('alert-modal').style.display = 'none';
    };
});