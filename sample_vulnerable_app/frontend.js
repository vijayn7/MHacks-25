
// Vulnerable JavaScript frontend
class UserAPI {
    constructor() {
        this.baseUrl = 'http://localhost:5000';
    }
    
    // XSS vulnerability - no input sanitization
    displayUserData(userData) {
        const userDiv = document.getElementById('user-info');
        userDiv.innerHTML = `
            <h2>Welcome ${userData.username}!</h2>
            <p>Email: ${userData.email}</p>
            <p>User ID: ${userData.id}</p>
        `;
    }
    
    // Insecure API call - no CSRF protection
    async login(username, password) {
        const response = await fetch(`${this.baseUrl}/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `username=${username}&password=${password}`
        });
        
        return response.json();
    }
    
    // IDOR vulnerability - accessing other users' data
    async getUserData(userId) {
        const response = await fetch(`${this.baseUrl}/user/${userId}`);
        return response.json();
    }
    
    // Insecure file upload
    async uploadFile(file) {
        const formData = new FormData();
        formData.append('file', file);
        
        const response = await fetch(`${this.baseUrl}/upload`, {
            method: 'POST',
            body: formData
        });
        
        return response.json();
    }
}

// Global instance
window.userAPI = new UserAPI();
